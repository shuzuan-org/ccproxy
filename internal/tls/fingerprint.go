package tls

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

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

	// Dial TCP
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	tcpConn, err := net.DialTimeout("tcp", addr, 30*time.Second)
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
