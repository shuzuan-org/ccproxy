package netutil

import (
	"testing"
)

func TestMaskProxyURL_ValidURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"host:port", "socks5://10.0.0.1:1080", "10.0.0.1:1080"},
		{"with auth", "socks5://user:pass@10.0.0.1:1080", "10.0.0.1:1080"},
		{"no port", "socks5://myhost", "myhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MaskProxyURL(tc.url)
			if got != tc.want {
				t.Errorf("MaskProxyURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestMaskProxyURL_InvalidURL(t *testing.T) {
	t.Parallel()
	got := MaskProxyURL("://bad")
	if got != "(invalid)" {
		t.Errorf("MaskProxyURL(bad) = %q, want (invalid)", got)
	}
}

func TestNewSOCKS5Dialer_ValidURL(t *testing.T) {
	t.Parallel()
	dialer, err := NewSOCKS5Dialer("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestNewSOCKS5Dialer_WithAuth(t *testing.T) {
	t.Parallel()
	dialer, err := NewSOCKS5Dialer("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestNewSOCKS5Dialer_InvalidURL(t *testing.T) {
	t.Parallel()
	_, err := NewSOCKS5Dialer("://bad")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
