package auth

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

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

// Middleware validates Bearer token from Authorization header
func Middleware(apiKeys []config.APIKeyConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAuthError(w, "Missing Authorization header")
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeAuthError(w, "Invalid Authorization header format")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" {
				writeAuthError(w, "Empty bearer token")
				return
			}

			// Find matching API key using constant-time comparison
			var matched *config.APIKeyConfig
			for i := range apiKeys {
				if apiKeys[i].Enabled && subtle.ConstantTimeCompare([]byte(apiKeys[i].Key), []byte(token)) == 1 {
					matched = &apiKeys[i]
					break
				}
			}

			if matched == nil {
				slog.Warn("auth rejected: invalid API key",
					"remote", r.RemoteAddr,
					"path", r.URL.Path,
				)
				writeAuthError(w, "Invalid API key")
				return
			}

			ctx := context.WithValue(r.Context(), authInfoKey, AuthInfo{APIKeyName: matched.Name})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"` + message + `"}}`))
}
