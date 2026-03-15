package tls

import (
	"testing"
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
	// Full Node.js 20.x + OpenSSL 3.x profile: 56 cipher suites covering
	// TLS 1.3, ECDHE, DHE, DHE-DSS, AES-CCM, ARIA, and legacy RSA.
	if got := len(spec.CipherSuites); got != 56 {
		t.Errorf("expected 56 cipher suites, got %d", got)
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
