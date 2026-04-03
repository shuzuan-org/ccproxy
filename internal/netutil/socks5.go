package netutil

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// NewSOCKS5Dialer parses a SOCKS5 proxy URL and returns a dialer.
// The URL format is socks5://[user:pass@]host:port or socks5h://[user:pass@]host:port.
// Both schemes behave identically — Go's proxy.SOCKS5 always sends the raw hostname
// to the proxy server for remote DNS resolution.
func NewSOCKS5Dialer(proxyURL string) (proxy.Dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL %q: %w", proxyURL, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme %q, want socks5 or socks5h", u.Scheme)
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
	return dialer, nil
}

// MaskProxyURL returns the proxy host for logging, stripping credentials.
func MaskProxyURL(proxyURL string) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "(invalid)"
	}
	return u.Host
}
