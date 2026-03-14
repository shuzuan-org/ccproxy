package observe

import (
	"context"
	"log/slog"
)

// RequestContext carries per-request identity for correlation in logs and headers.
type RequestContext struct {
	RequestID  string
	APIKeyName string
	SessionKey string
}

type contextKey struct{}

// WithRequestContext attaches a RequestContext to the context.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, contextKey{}, rc)
}

// GetRequestContext retrieves the RequestContext from context, or nil if absent.
func GetRequestContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(contextKey{}).(*RequestContext)
	return rc
}

// Logger returns an slog.Logger with request_id and api_key fields pre-attached.
// If ctx has no RequestContext, returns slog.Default().
func Logger(ctx context.Context) *slog.Logger {
	rc := GetRequestContext(ctx)
	if rc == nil {
		return slog.Default()
	}
	return slog.Default().With(
		"request_id", rc.RequestID,
		"api_key", rc.APIKeyName,
	)
}
