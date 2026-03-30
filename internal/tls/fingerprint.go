package tls

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/netutil"
	utls "github.com/refraction-networking/utls"
)

// proxyURLKey is the context key for per-request SOCKS5 proxy URL.
type proxyURLKey struct{}

// WithProxyURL returns a context carrying the given SOCKS5 proxy URL.
func WithProxyURL(ctx context.Context, proxyURL string) context.Context {
	return context.WithValue(ctx, proxyURLKey{}, proxyURL)
}

// ProxyURLFromContext extracts the SOCKS5 proxy URL from context, or "".
func ProxyURLFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(proxyURLKey{}).(string); ok {
		return v
	}
	return ""
}

// NewTransport creates an HTTP transport that uses utls to mimic
// Claude CLI's TLS fingerprint (Node.js 24.x).
// Connections are pooled per proxy URL for efficient reuse.
func NewTransport() http.RoundTripper {
	return &fingerprintTransport{
		transports: make(map[string]*http.Transport),
	}
}

type fingerprintTransport struct {
	mu         sync.Mutex
	transports map[string]*http.Transport // proxyURL → pooled transport
}

func (t *fingerprintTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// For non-HTTPS requests, fall back to standard transport.
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	proxyURL := ProxyURLFromContext(req.Context())
	tr := t.getOrCreateTransport(proxyURL)
	return tr.RoundTrip(req)
}

// getOrCreateTransport returns a pooled *http.Transport for the given proxyURL.
// An empty proxyURL means direct connection (no proxy).
func (t *fingerprintTransport) getOrCreateTransport(proxyURL string) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tr, ok := t.transports[proxyURL]; ok {
		return tr
	}

	tr := &http.Transport{
		DialTLSContext:      t.makeDialTLSContext(proxyURL),
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	t.transports[proxyURL] = tr
	return tr
}

// makeDialTLSContext returns a DialTLSContext function bound to a specific proxyURL.
func (t *fingerprintTransport) makeDialTLSContext(proxyURL string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Dial TCP (directly or via SOCKS5 proxy)
		tcpConn, err := dialTCP(ctx, addr, proxyURL)
		if err != nil {
			return nil, err
		}

		// Extract hostname for SNI
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("split host port %q: %w", addr, err)
		}

		// Create a fresh spec per connection — utls mutates the spec during handshake
		// (e.g. filling KeyShare key material), so reusing a spec causes failures.
		spec := claudeCLIv2Spec()

		// Apply utls handshake
		tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(spec); err != nil {
			_ = tcpConn.Close()
			slog.Error("tls: utls preset failed", "host", host, "error", err.Error())
			return nil, err
		}
		handshakeStart := time.Now()
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close()
			slog.Error("tls: handshake failed", "host", host, "elapsed", time.Since(handshakeStart).String(), "error", err.Error())
			return nil, err
		}
		slog.Debug("tls: handshake success",
			"host", host,
			"proto", tlsConn.ConnectionState().NegotiatedProtocol,
			"via_proxy", proxyURL != "",
			"elapsed", time.Since(handshakeStart).String(),
		)

		return tlsConn, nil
	}
}

// dialTCP establishes a TCP connection, optionally via a SOCKS5 proxy.
func dialTCP(ctx context.Context, addr string, proxyURL string) (net.Conn, error) {
	if proxyURL == "" {
		slog.Debug("tls: dialing direct", "addr", addr)
		start := time.Now()
		d := &net.Dialer{Timeout: 30 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			slog.Error("tls: direct dial failed", "addr", addr, "elapsed", time.Since(start).String(), "error", err.Error())
			return nil, err
		}
		slog.Debug("tls: direct dial success", "addr", addr, "elapsed", time.Since(start).String())
		return conn, nil
	}

	proxyHost := netutil.MaskProxyURL(proxyURL)
	slog.Debug("tls: dialing via SOCKS5", "proxy_host", proxyHost, "target", addr)

	dialer, err := netutil.NewSOCKS5Dialer(proxyURL)
	if err != nil {
		slog.Error("tls: SOCKS5 dialer creation failed", "error", err.Error())
		return nil, err
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		slog.Error("tls: SOCKS5 dial failed", "proxy_host", proxyHost, "target", addr, "elapsed", time.Since(start).String(), "error", err.Error())
		return nil, err
	}
	slog.Debug("tls: SOCKS5 dial success", "proxy_host", proxyHost, "target", addr, "elapsed", time.Since(start).String())
	return conn, nil
}

var (
	defaultCipherSuites = []uint16{
		0x1301,
		0x1302,
		0x1303,
		0xc02b,
		0xc02f,
		0xc02c,
		0xc030,
		0xcca9,
		0xcca8,
		0xc009,
		0xc013,
		0xc00a,
		0xc014,
		0x009c,
		0x009d,
		0x002f,
		0x0035,
	}
	defaultCurves = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}
	defaultPointFormats = []uint16{0}
	defaultSignatureAlgorithms = []utls.SignatureScheme{
		0x0403,
		0x0804,
		0x0401,
		0x0503,
		0x0805,
		0x0501,
		0x0806,
		0x0601,
		0x0201,
	}
)

func toUint8s(vals []uint16) []uint8 {
	out := make([]uint8, len(vals))
	for i, v := range vals {
		out[i] = uint8(v)
	}
	return out
}

func buildDefaultExtensions() []utls.TLSExtension {
	keyShares := []utls.KeyShare{{Group: utls.X25519}}
	return []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.GREASEEncryptedClientHelloExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{},
		&utls.SupportedCurvesExtension{Curves: append([]utls.CurveID(nil), defaultCurves...)},
		&utls.SupportedPointsExtension{SupportedPoints: toUint8s(defaultPointFormats)},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: append([]utls.SignatureScheme(nil), defaultSignatureAlgorithms...)},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: keyShares},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{uint8(utls.PskModeDHE)}},
		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
	}
}

func claudeCLIv2Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), defaultCipherSuites...),
		CompressionMethods: []uint8{0},
		Extensions:         buildDefaultExtensions(),
		TLSVersMax:         utls.VersionTLS13,
		TLSVersMin:         utls.VersionTLS10,
	}
}
