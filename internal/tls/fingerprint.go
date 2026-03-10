package tls

import (
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// NewTransport creates an HTTP transport. If fingerprintEnabled is true,
// it uses utls to mimic Claude CLI's TLS fingerprint (Node.js 20.x + OpenSSL 3.x).
func NewTransport(fingerprintEnabled bool) http.RoundTripper {
	if !fingerprintEnabled {
		return &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	return &fingerprintTransport{
		spec: claudeCLIv2Spec(),
	}
}

type fingerprintTransport struct {
	spec *utls.ClientHelloSpec
}

func (t *fingerprintTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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

	// Apply utls handshake
	tlsConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(t.spec); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}

	// Create a one-shot transport that uses this connection
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		// Disable connection reuse for fingerprinted connections
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
