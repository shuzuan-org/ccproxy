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

func TestNewTransport_FingerprintedHasSpec(t *testing.T) {
	tr := NewTransport(true)
	fp, ok := tr.(*fingerprintTransport)
	if !ok {
		t.Fatalf("expected *fingerprintTransport, got %T", tr)
	}
	if fp.spec == nil {
		t.Fatal("expected non-nil ClientHelloSpec")
	}
	if len(fp.spec.CipherSuites) == 0 {
		t.Fatal("expected non-empty CipherSuites in spec")
	}
	if len(fp.spec.Extensions) == 0 {
		t.Fatal("expected non-empty Extensions in spec")
	}
}
