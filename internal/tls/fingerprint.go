package tls

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
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
// Claude CLI's TLS fingerprint (Node.js 20.x + OpenSSL 3.x).
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

	u, err := url.Parse(proxyURL)
	if err != nil {
		slog.Error("tls: invalid proxy URL", "proxy", proxyURL, "error", err.Error())
		return nil, fmt.Errorf("parse proxy URL %q: %w", proxyURL, err)
	}

	// Log proxy host only, never credentials.
	slog.Debug("tls: dialing via SOCKS5", "proxy_host", u.Host, "has_auth", u.User != nil, "target", addr)

	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		slog.Error("tls: SOCKS5 dialer creation failed", "proxy_host", u.Host, "error", err.Error())
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	start := time.Now()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		slog.Error("tls: SOCKS5 dial failed", "proxy_host", u.Host, "target", addr, "elapsed", time.Since(start).String(), "error", err.Error())
		return nil, err
	}
	slog.Debug("tls: SOCKS5 dial success", "proxy_host", u.Host, "target", addr, "elapsed", time.Since(start).String())
	return conn, nil
}

func claudeCLIv2Spec() *utls.ClientHelloSpec {
	// Simplified Claude CLI v2 TLS profile
	// Based on Node.js 20.x + OpenSSL 3.x
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 ciphers
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			// TLS 1.2 ciphers (ECDHE)
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// Legacy
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
					utls.CurveP521,
				},
			},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.ExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					0x0807, // ed25519
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
				},
			},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12},
			},
			&utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{utls.PskModeDHE},
			},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{Group: utls.X25519},
				},
			},
		},
	}
}
