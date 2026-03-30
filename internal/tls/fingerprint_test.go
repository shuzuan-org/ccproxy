package tls

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestNewTransport(t *testing.T) {
	tr := NewTransport()
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	_, ok := tr.(*fingerprintTransport)
	if !ok {
		t.Fatalf("expected *fingerprintTransport, got %T", tr)
	}
}

func TestClaudeCLIv2Spec(t *testing.T) {
	spec := claudeCLIv2Spec()
	if spec == nil {
		t.Fatal("expected non-nil ClientHelloSpec")
	}
	if len(spec.CipherSuites) == 0 {
		t.Fatal("expected non-empty CipherSuites in spec")
	}
	if len(spec.Extensions) == 0 {
		t.Fatal("expected non-empty Extensions in spec")
	}
}

func TestClaudeCLIv2Spec_FreshPerCall(t *testing.T) {
	spec1 := claudeCLIv2Spec()
	spec2 := claudeCLIv2Spec()
	if spec1 == spec2 {
		t.Fatal("expected distinct spec objects per call")
	}
}

func TestClaudeCLIv2Spec_CipherSuiteCount(t *testing.T) {
	spec := claudeCLIv2Spec()
	if got := len(spec.CipherSuites); got != 17 {
		t.Errorf("expected 17 cipher suites, got %d", got)
	}
}

func TestClaudeCLIv2Spec_TLSVersionRange(t *testing.T) {
	spec := claudeCLIv2Spec()
	// Node.js defaults: TLS 1.0 min, TLS 1.3 max.
	if spec.TLSVersMin != 0x0301 { // VersionTLS10
		t.Errorf("expected TLSVersMin=TLS1.0 (0x0301), got 0x%04x", spec.TLSVersMin)
	}
	if spec.TLSVersMax != 0x0304 { // VersionTLS13
		t.Errorf("expected TLSVersMax=TLS1.3 (0x0304), got 0x%04x", spec.TLSVersMax)
	}
}

func TestClaudeCLIv2Spec_NoDuplicateCiphers(t *testing.T) {
	spec := claudeCLIv2Spec()
	seen := make(map[uint16]bool, len(spec.CipherSuites))
	for _, cs := range spec.CipherSuites {
		if seen[cs] {
			t.Errorf("duplicate cipher suite: 0x%04x", cs)
		}
		seen[cs] = true
	}
}

func TestWithProxyURL_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	proxyURL := "socks5://10.0.0.1:1080"
	ctx = WithProxyURL(ctx, proxyURL)
	got := ProxyURLFromContext(ctx)
	if got != proxyURL {
		t.Errorf("ProxyURLFromContext = %q, want %q", got, proxyURL)
	}
}

func TestProxyURLFromContext_Missing(t *testing.T) {
	t.Parallel()
	got := ProxyURLFromContext(context.Background())
	if got != "" {
		t.Errorf("ProxyURLFromContext(empty) = %q, want empty", got)
	}
}

func TestGetOrCreateTransport_Caching(t *testing.T) {
	t.Parallel()
	ft := &fingerprintTransport{transports: make(map[string]*http.Transport)}
	tr1 := ft.getOrCreateTransport("")
	tr2 := ft.getOrCreateTransport("")
	if tr1 != tr2 {
		t.Error("expected same transport for same proxyURL")
	}
}

func TestGetOrCreateTransport_DifferentProxy(t *testing.T) {
	t.Parallel()
	ft := &fingerprintTransport{transports: make(map[string]*http.Transport)}
	tr1 := ft.getOrCreateTransport("")
	tr2 := ft.getOrCreateTransport("socks5://proxy:1080")
	if tr1 == tr2 {
		t.Error("expected different transports for different proxyURLs")
	}
}

// ja3Hash computes the JA3 hash from a utls ClientHelloSpec.
// JA3 = MD5(SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats)
// where values within each field are separated by "-".
func ja3Hash(spec *utls.ClientHelloSpec) string {
	// For TLS 1.3, ClientHello.legacy_version = 0x0303 = 771.
	version := "771"

	// Cipher suites
	ciphers := make([]string, len(spec.CipherSuites))
	for i, c := range spec.CipherSuites {
		ciphers[i] = strconv.FormatUint(uint64(c), 10)
	}

	// Extensions, curves, point formats
	var extIDs, curveIDs, pointFmts []string
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			extIDs = append(extIDs, "0")
		case *utls.GREASEEncryptedClientHelloExtension:
			extIDs = append(extIDs, "65037")
		case *utls.StatusRequestExtension:
			extIDs = append(extIDs, "5")
		case *utls.SupportedPointsExtension:
			extIDs = append(extIDs, "11")
			for _, p := range e.SupportedPoints {
				pointFmts = append(pointFmts, strconv.Itoa(int(p)))
			}
		case *utls.SupportedCurvesExtension:
			extIDs = append(extIDs, "10")
			for _, c := range e.Curves {
				curveIDs = append(curveIDs, strconv.FormatUint(uint64(c), 10))
			}
		case *utls.SessionTicketExtension:
			extIDs = append(extIDs, "35")
		case *utls.ALPNExtension:
			extIDs = append(extIDs, "16")
		case *utls.ExtendedMasterSecretExtension:
			extIDs = append(extIDs, "23")
		case *utls.RenegotiationInfoExtension:
			extIDs = append(extIDs, "65281")
		case *utls.GenericExtension:
			extIDs = append(extIDs, strconv.Itoa(int(e.Id)))
		case *utls.SignatureAlgorithmsExtension:
			extIDs = append(extIDs, "13")
		case *utls.SCTExtension:
			extIDs = append(extIDs, "18")
		case *utls.SupportedVersionsExtension:
			extIDs = append(extIDs, "43")
		case *utls.PSKKeyExchangeModesExtension:
			extIDs = append(extIDs, "45")
		case *utls.KeyShareExtension:
			extIDs = append(extIDs, "51")
		default:
			panic(fmt.Sprintf("ja3Hash: unhandled extension type %T", ext))
		}
	}

	ja3 := fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extIDs, "-"),
		strings.Join(curveIDs, "-"),
		strings.Join(pointFmts, "-"),
	)

	hash := md5.Sum([]byte(ja3))
	return fmt.Sprintf("%x", hash)
}

func TestClaudeCLIv2Spec_JA3Hash(t *testing.T) {
	t.Parallel()
	const expectedJA3 = "44f88fca027f27bab4bb08d4af15f23e"

	spec := claudeCLIv2Spec()
	got := ja3Hash(spec)
	if got != expectedJA3 {
		t.Errorf("JA3 hash mismatch:\n  got:  %s\n  want: %s", got, expectedJA3)
	}
}

func TestClaudeCLIv2Spec_DefaultALPN(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("unexpected ALPN protocols: %#v", alpn.AlpnProtocols)
			}
			return
		}
	}
	t.Fatal("expected ALPNExtension")
}

func TestClaudeCLIv2Spec_DefaultSupportedVersions(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if versions, ok := ext.(*utls.SupportedVersionsExtension); ok {
			want := []uint16{utls.VersionTLS13, utls.VersionTLS12}
			if len(versions.Versions) != len(want) {
				t.Fatalf("supported versions len=%d want=%d", len(versions.Versions), len(want))
			}
			for i := range want {
				if versions.Versions[i] != want[i] {
					t.Fatalf("supported version[%d]=0x%04x want 0x%04x", i, versions.Versions[i], want[i])
				}
			}
			return
		}
	}
	t.Fatal("expected SupportedVersionsExtension")
}

func TestClaudeCLIv2Spec_DefaultKeyShare(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			if len(ks.KeyShares) != 1 || ks.KeyShares[0].Group != utls.X25519 {
				t.Fatalf("unexpected key shares: %#v", ks.KeyShares)
			}
			return
		}
	}
	t.Fatal("expected KeyShareExtension")
}

func TestClaudeCLIv2Spec_DefaultIncludesECH(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return
		}
	}
	t.Fatal("expected GREASEEncryptedClientHelloExtension")
}

func TestClaudeCLIv2Spec_DefaultHasNoGREASEBookends(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.UtlsGREASEExtension); ok {
			t.Fatal("did not expect UtlsGREASEExtension in default spec")
		}
	}
}

func TestRoundTrip_NonHTTPS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewTransport()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
