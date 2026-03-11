package tls

import (
	"net/http"
	"testing"
)

func TestNewTransport_Standard(t *testing.T) {
	tr := NewTransport(false)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	_, ok := tr.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", tr)
	}
}

func TestNewTransport_Fingerprinted(t *testing.T) {
	tr := NewTransport(true)
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
		t.Fatal("expected distinct spec instances per call")
	}
}
