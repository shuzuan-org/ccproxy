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
		t.Fatal("expected distinct spec instances per call")
	}
}
