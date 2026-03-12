package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
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
func NewTransport() http.RoundTripper {
	return &fingerprintTransport{}
}

type fingerprintTransport struct{}

func (t *fingerprintTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// For non-HTTPS requests, fall back to standard transport.
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	// Dial TCP (directly or via SOCKS5 proxy)
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	tcpConn, err := dialTCP(req.Context(), addr)
	if err != nil {
		return nil, err
	}

	// Create a fresh spec per request — utls mutates the spec during handshake
	// (e.g. filling KeyShare key material), so reusing a spec causes failures.
	spec := claudeCLIv2Spec()

	// Apply utls handshake
	tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(spec); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	// Check negotiated protocol and use the appropriate transport
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		// HTTP/2: use x/net/http2 transport with pre-established connection
		h2Transport := &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		}
		h2Conn, err := h2Transport.NewClientConn(tlsConn)
		if err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		return h2Conn.RoundTrip(req)
	}

	// HTTP/1.1 fallback: create a one-shot transport that uses this connection
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		DisableKeepAlives: true,
	}

	return tr.RoundTrip(req)
}

// dialTCP establishes a TCP connection, optionally via a SOCKS5 proxy
// specified in the request context.
func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	proxyURL := ProxyURLFromContext(ctx)
	if proxyURL == "" {
		return net.DialTimeout("tcp", addr, 30*time.Second)
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL %q: %w", proxyURL, err)
	}

	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	return dialer.Dial("tcp", addr)
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
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
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
