package auth

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/binn/ccproxy/internal/apierror"
	"github.com/binn/ccproxy/internal/config"
)

type AuthInfo struct {
	APIKeyName string
}

type contextKey string

const authInfoKey contextKey = "auth_info"

// GetAuthInfo retrieves auth info from request context
func GetAuthInfo(ctx context.Context) (AuthInfo, bool) {
	info, ok := ctx.Value(authInfoKey).(AuthInfo)
	return info, ok
}

// extractToken returns the bearer token from the request, checking
// Authorization header first, then x-api-key header as fallback.
func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	return r.Header.Get("x-api-key")
}

// Middleware validates bearer token from Authorization or x-api-key header.
func Middleware(apiKeys []config.APIKeyConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				apierror.Write(w, http.StatusUnauthorized, "authentication_error", "Missing API key: provide via Authorization header or x-api-key header")
				return
			}

			// Find matching API key using constant-time comparison.
			// Iterate ALL keys without early exit to prevent timing oracles.
			var matched *config.APIKeyConfig
			for i := range apiKeys {
				if apiKeys[i].Enabled && subtle.ConstantTimeCompare([]byte(apiKeys[i].Key), []byte(token)) == 1 {
					matched = &apiKeys[i]
				}
			}

			if matched == nil {
				slog.Warn("auth rejected: invalid API key",
					"remote", r.RemoteAddr,
					"path", r.URL.Path,
				)
				apierror.Write(w, http.StatusUnauthorized, "authentication_error", "Invalid API key")
				return
			}

			ctx := context.WithValue(r.Context(), authInfoKey, AuthInfo{APIKeyName: matched.Name})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
