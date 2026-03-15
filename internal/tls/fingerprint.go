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

// Cipher suite IDs not built into utls — defined via FakeCipherSuite.
// These match the full Node.js 20.x + OpenSSL 3.x cipher list.
const (
	cipher_DHE_RSA_AES_256_GCM_SHA384         = 0x009f
	cipher_DHE_RSA_CHACHA20_POLY1305_SHA256   = 0xccaa
	cipher_DHE_RSA_AES_128_GCM_SHA256         = 0x009e
	cipher_DHE_RSA_AES_256_CBC_SHA256         = 0x006b
	cipher_DHE_RSA_AES_128_CBC_SHA256         = 0x0067
	cipher_DHE_RSA_AES_256_CBC_SHA            = 0x0039
	cipher_DHE_RSA_AES_128_CBC_SHA            = 0x0033
	cipher_DHE_DSS_AES_256_GCM_SHA384        = 0x00a3
	cipher_DHE_DSS_AES_128_GCM_SHA256        = 0x00a2
	cipher_DHE_DSS_AES_256_CBC_SHA256        = 0x006a
	cipher_DHE_DSS_AES_128_CBC_SHA256        = 0x0040
	cipher_DHE_DSS_AES_256_CBC_SHA           = 0x0038
	cipher_DHE_DSS_AES_128_CBC_SHA           = 0x0032
	cipher_ECDHE_ECDSA_AES_256_CBC_SHA384    = 0xc024
	cipher_ECDHE_ECDSA_AES_128_CBC_SHA256    = 0xc023
	cipher_ECDHE_RSA_AES_256_CBC_SHA384      = 0xc028
	cipher_ECDHE_RSA_AES_128_CBC_SHA256      = 0xc027
	cipher_RSA_AES_256_GCM_SHA384            = 0x009d
	cipher_RSA_AES_128_GCM_SHA256            = 0x009c
	cipher_RSA_AES_256_CBC_SHA256            = 0x003d
	cipher_RSA_AES_128_CBC_SHA256            = 0x003c
	cipher_RSA_AES_256_CBC_SHA               = 0x0035
	cipher_RSA_AES_128_CBC_SHA               = 0x002f
	cipher_AES_128_CCM_SHA256                = 0x1304
	cipher_AES_128_CCM_8_SHA256              = 0x1305
	cipher_ECDHE_ECDSA_AES_128_CCM          = 0xc0ac
	cipher_ECDHE_ECDSA_AES_128_CCM_8        = 0xc0ae
	cipher_ECDHE_ECDSA_AES_256_CCM          = 0xc0ad
	cipher_ECDHE_ECDSA_AES_256_CCM_8        = 0xc0af
	cipher_DHE_RSA_AES_128_CCM              = 0xc09e
	cipher_DHE_RSA_AES_128_CCM_8            = 0xc0a2
	cipher_DHE_RSA_AES_256_CCM              = 0xc09f
	cipher_DHE_RSA_AES_256_CCM_8            = 0xc0a3
	// ARIA GCM cipher suites (RFC 6209)
	cipher_ECDHE_ECDSA_ARIA_128_GCM = 0xc05c
	cipher_ECDHE_ECDSA_ARIA_256_GCM = 0xc05d
	cipher_ECDHE_RSA_ARIA_128_GCM   = 0xc060
	cipher_ECDHE_RSA_ARIA_256_GCM   = 0xc061
	cipher_DHE_RSA_ARIA_128_GCM     = 0xc052
	cipher_DHE_RSA_ARIA_256_GCM     = 0xc053
	cipher_DHE_DSS_ARIA_128_GCM     = 0xc056
	cipher_DHE_DSS_ARIA_256_GCM     = 0xc057
	cipher_RSA_ARIA_128_GCM         = 0xc050
	cipher_RSA_ARIA_256_GCM         = 0xc051

	// ffdhe named groups (RFC 7919)
	ffdhe2048 utls.CurveID = 0x0100
	ffdhe3072 utls.CurveID = 0x0101
	ffdhe4096 utls.CurveID = 0x0102
	ffdhe6144 utls.CurveID = 0x0103
	ffdhe8192 utls.CurveID = 0x0104
)

func claudeCLIv2Spec() *utls.ClientHelloSpec {
	// Full Claude CLI v2 TLS profile — aligned with Node.js 20.x + OpenSSL 3.x.
	// 59 cipher suites matching the real fingerprint.
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS10,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 ciphers
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			cipher_AES_128_CCM_SHA256,
			cipher_AES_128_CCM_8_SHA256,

			// ECDHE-ECDSA
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			cipher_ECDHE_ECDSA_AES_128_CCM,
			cipher_ECDHE_ECDSA_AES_128_CCM_8,
			cipher_ECDHE_ECDSA_AES_256_CCM,
			cipher_ECDHE_ECDSA_AES_256_CCM_8,

			// ECDHE-RSA
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// DHE-RSA
			cipher_DHE_RSA_AES_256_GCM_SHA384,
			cipher_DHE_RSA_CHACHA20_POLY1305_SHA256,
			cipher_DHE_RSA_AES_128_GCM_SHA256,
			cipher_DHE_RSA_AES_128_CCM,
			cipher_DHE_RSA_AES_128_CCM_8,
			cipher_DHE_RSA_AES_256_CCM,
			cipher_DHE_RSA_AES_256_CCM_8,

			// DHE-DSS
			cipher_DHE_DSS_AES_256_GCM_SHA384,
			cipher_DHE_DSS_AES_128_GCM_SHA256,

			// ECDHE-ECDSA CBC
			cipher_ECDHE_ECDSA_AES_256_CBC_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			cipher_ECDHE_ECDSA_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

			// ECDHE-RSA CBC
			cipher_ECDHE_RSA_AES_256_CBC_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			cipher_ECDHE_RSA_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

			// DHE-RSA CBC
			cipher_DHE_RSA_AES_256_CBC_SHA256,
			cipher_DHE_RSA_AES_256_CBC_SHA,
			cipher_DHE_RSA_AES_128_CBC_SHA256,
			cipher_DHE_RSA_AES_128_CBC_SHA,

			// DHE-DSS CBC
			cipher_DHE_DSS_AES_256_CBC_SHA256,
			cipher_DHE_DSS_AES_256_CBC_SHA,
			cipher_DHE_DSS_AES_128_CBC_SHA256,
			cipher_DHE_DSS_AES_128_CBC_SHA,

			// Legacy RSA
			cipher_RSA_AES_256_GCM_SHA384,
			cipher_RSA_AES_128_GCM_SHA256,
			cipher_RSA_AES_256_CBC_SHA256,
			cipher_RSA_AES_256_CBC_SHA,
			cipher_RSA_AES_128_CBC_SHA256,
			cipher_RSA_AES_128_CBC_SHA,

			// ARIA (ECDHE)
			cipher_ECDHE_ECDSA_ARIA_256_GCM,
			cipher_ECDHE_ECDSA_ARIA_128_GCM,
			cipher_ECDHE_RSA_ARIA_256_GCM,
			cipher_ECDHE_RSA_ARIA_128_GCM,

			// ARIA (DHE)
			cipher_DHE_RSA_ARIA_256_GCM,
			cipher_DHE_RSA_ARIA_128_GCM,
			cipher_DHE_DSS_ARIA_256_GCM,
			cipher_DHE_DSS_ARIA_128_GCM,

			// ARIA (RSA)
			cipher_RSA_ARIA_256_GCM,
			cipher_RSA_ARIA_128_GCM,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{
				SupportedPoints: []byte{
					0, // uncompressed
					1, // ansiX962_compressed_prime
					2, // ansiX962_compressed_char2
				},
			},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
					utls.CurveP521,
					0x001d, // x448
					ffdhe2048,
					ffdhe3072,
					ffdhe4096,
					ffdhe6144,
					ffdhe8192,
				},
			},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.ExtendedMasterSecretExtension{},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					0x0807, // ed25519
					0x0808, // ed448
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
					// SHA224 series
					0x0303, // ecdsa_secp256r1_sha224 (non-standard, OpenSSL compat)
					0x0301, // rsa_pkcs1_sha224
					// DSA series
					0x0602, // dsa_sha256
					0x0502, // dsa_sha384 (non-standard)
					0x0402, // dsa_sha512 (non-standard)
					0x0302, // dsa_sha224
					0x0202, // dsa_sha1
					// Legacy
					0x0201, // rsa_pkcs1_sha1
					0x0203, // ecdsa_sha1
				},
			},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12, utls.VersionTLS11, utls.VersionTLS10},
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
		GetSessionID: nil,
	}
}
