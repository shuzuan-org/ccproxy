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
	// RSA AES-CCM cipher suites (RFC 6655)
	cipher_RSA_AES_256_CCM_8 = 0xc0a1
	cipher_RSA_AES_256_CCM   = 0xc09d
	cipher_RSA_AES_128_CCM_8 = 0xc0a0
	cipher_RSA_AES_128_CCM   = 0xc09c
	// Renegotiation indication (RFC 5746)
	cipher_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff

	// ffdhe named groups (RFC 7919)
	ffdhe2048 utls.CurveID = 0x0100
	ffdhe3072 utls.CurveID = 0x0101
	ffdhe4096 utls.CurveID = 0x0102
	ffdhe6144 utls.CurveID = 0x0103
	ffdhe8192 utls.CurveID = 0x0104
)

func claudeCLIv2Spec() *utls.ClientHelloSpec {
	// Full Claude CLI v2 TLS profile — captured from Node.js 20.x + OpenSSL 3.x.
	// 59 cipher suites in OpenSSL priority order. Order is critical for JA3 matching.
	// Expected JA3 hash: 1a28e69016765d92e3b381168d68922c
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS10,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 (MUST be first)
			utls.TLS_AES_256_GCM_SHA384,       // 0x1302
			utls.TLS_CHACHA20_POLY1305_SHA256,  // 0x1303
			utls.TLS_AES_128_GCM_SHA256,        // 0x1301

			// ECDHE + AES-GCM
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    // 0xc02f
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // 0xc02b
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,    // 0xc030
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // 0xc02c

			// DHE + AES-GCM
			cipher_DHE_RSA_AES_128_GCM_SHA256,  // 0x009e

			// ECDHE/DHE + AES-CBC-SHA256/384
			cipher_ECDHE_RSA_AES_128_CBC_SHA256,   // 0xc027
			cipher_DHE_RSA_AES_128_CBC_SHA256,     // 0x0067
			cipher_ECDHE_RSA_AES_256_CBC_SHA384,   // 0xc028
			cipher_DHE_RSA_AES_256_CBC_SHA256,     // 0x006b

			// DHE-DSS/RSA + AES-GCM
			cipher_DHE_DSS_AES_256_GCM_SHA384,  // 0x00a3
			cipher_DHE_RSA_AES_256_GCM_SHA384,  // 0x009f

			// ChaCha20-Poly1305
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,  // 0xcca9
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,    // 0xcca8
			cipher_DHE_RSA_CHACHA20_POLY1305_SHA256,       // 0xccaa

			// AES-CCM (256-bit)
			cipher_ECDHE_ECDSA_AES_256_CCM_8,  // 0xc0af
			cipher_ECDHE_ECDSA_AES_256_CCM,    // 0xc0ad
			cipher_DHE_RSA_AES_256_CCM_8,      // 0xc0a3
			cipher_DHE_RSA_AES_256_CCM,        // 0xc09f

			// ARIA (256-bit)
			cipher_ECDHE_ECDSA_ARIA_256_GCM,  // 0xc05d
			cipher_ECDHE_RSA_ARIA_256_GCM,    // 0xc061
			cipher_DHE_DSS_ARIA_256_GCM,      // 0xc057
			cipher_DHE_RSA_ARIA_256_GCM,      // 0xc053

			// DHE-DSS + AES-GCM (128-bit)
			cipher_DHE_DSS_AES_128_GCM_SHA256,  // 0x00a2

			// AES-CCM (128-bit)
			cipher_ECDHE_ECDSA_AES_128_CCM_8,  // 0xc0ae
			cipher_ECDHE_ECDSA_AES_128_CCM,    // 0xc0ac
			cipher_DHE_RSA_AES_128_CCM_8,      // 0xc0a2
			cipher_DHE_RSA_AES_128_CCM,        // 0xc09e

			// ARIA (128-bit)
			cipher_ECDHE_ECDSA_ARIA_128_GCM,  // 0xc05c
			cipher_ECDHE_RSA_ARIA_128_GCM,    // 0xc060
			cipher_DHE_DSS_ARIA_128_GCM,      // 0xc056
			cipher_DHE_RSA_ARIA_128_GCM,      // 0xc052

			// ECDHE/DHE + AES-CBC-SHA384/256 (more)
			cipher_ECDHE_ECDSA_AES_256_CBC_SHA384,  // 0xc024
			cipher_DHE_DSS_AES_256_CBC_SHA256,      // 0x006a
			cipher_ECDHE_ECDSA_AES_128_CBC_SHA256,  // 0xc023
			cipher_DHE_DSS_AES_128_CBC_SHA256,      // 0x0040

			// ECDHE/DHE + AES-CBC-SHA (legacy)
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,  // 0xc00a
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,    // 0xc014
			cipher_DHE_RSA_AES_256_CBC_SHA,              // 0x0039
			cipher_DHE_DSS_AES_256_CBC_SHA,              // 0x0038
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,  // 0xc009
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,    // 0xc013
			cipher_DHE_RSA_AES_128_CBC_SHA,              // 0x0033
			cipher_DHE_DSS_AES_128_CBC_SHA,              // 0x0032

			// RSA + AES-GCM/CCM/ARIA (non-PFS, 256-bit)
			cipher_RSA_AES_256_GCM_SHA384,  // 0x009d
			cipher_RSA_AES_256_CCM_8,       // 0xc0a1
			cipher_RSA_AES_256_CCM,         // 0xc09d
			cipher_RSA_ARIA_256_GCM,        // 0xc051

			// RSA + AES-GCM/CCM/ARIA (non-PFS, 128-bit)
			cipher_RSA_AES_128_GCM_SHA256,  // 0x009c
			cipher_RSA_AES_128_CCM_8,       // 0xc0a0
			cipher_RSA_AES_128_CCM,         // 0xc09c
			cipher_RSA_ARIA_128_GCM,        // 0xc050

			// RSA + AES-CBC (non-PFS, legacy)
			cipher_RSA_AES_256_CBC_SHA256,  // 0x003d
			cipher_RSA_AES_128_CBC_SHA256,  // 0x003c
			cipher_RSA_AES_256_CBC_SHA,     // 0x0035
			cipher_RSA_AES_128_CBC_SHA,     // 0x002f

			// Renegotiation indication
			cipher_EMPTY_RENEGOTIATION_INFO_SCSV,  // 0x00ff
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
					utls.X25519,          // 0x001d
					utls.CurveP256,       // 0x0017
					utls.CurveID(0x001e), // x448
					utls.CurveP521,       // 0x0019
					utls.CurveP384,       // 0x0018
					ffdhe2048,
					ffdhe3072,
					ffdhe4096,
					ffdhe6144,
					ffdhe8192,
				},
			},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac
			&utls.ExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					0x0403, // ecdsa_secp256r1_sha256
					0x0503, // ecdsa_secp384r1_sha384
					0x0603, // ecdsa_secp521r1_sha512
					0x0807, // ed25519
					0x0808, // ed448
					0x0809, // rsa_pss_pss_sha256
					0x080a, // rsa_pss_pss_sha384
					0x080b, // rsa_pss_pss_sha512
					0x0804, // rsa_pss_rsae_sha256
					0x0805, // rsa_pss_rsae_sha384
					0x0806, // rsa_pss_rsae_sha512
					0x0401, // rsa_pkcs1_sha256
					0x0501, // rsa_pkcs1_sha384
					0x0601, // rsa_pkcs1_sha512
					0x0303, // ecdsa_sha224
					0x0301, // rsa_pkcs1_sha224
					0x0302, // dsa_sha224
					0x0402, // dsa_sha256
					0x0502, // dsa_sha384
					0x0602, // dsa_sha512
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
		GetSessionID: nil,
	}
}
