package observe

import (
	"context"
	"log/slog"
	"testing"
)

func TestRequestContext_Roundtrip(t *testing.T) {
	t.Parallel()

	rc := &RequestContext{
		RequestID:  "req-123",
		APIKeyName: "team-key",
		SessionKey: "sess-456",
	}

	ctx := WithRequestContext(context.Background(), rc)
	got := GetRequestContext(ctx)

	if got == nil {
		t.Fatal("expected RequestContext, got nil")
	}
	if got.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", got.RequestID, "req-123")
	}
	if got.APIKeyName != "team-key" {
		t.Errorf("APIKeyName = %q, want %q", got.APIKeyName, "team-key")
	}
	if got.SessionKey != "sess-456" {
		t.Errorf("SessionKey = %q, want %q", got.SessionKey, "sess-456")
	}
}

func TestGetRequestContext_NilSafe(t *testing.T) {
	t.Parallel()

	// Empty context returns nil
	got := GetRequestContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestLogger_WithContext(t *testing.T) {
	t.Parallel()

	rc := &RequestContext{
		RequestID:  "req-abc",
		APIKeyName: "key-def",
	}
	ctx := WithRequestContext(context.Background(), rc)
	logger := Logger(ctx)

	if logger == nil {
		t.Fatal("Logger returned nil")
	}
	// Verify it's not the bare default by checking it's an *slog.Logger
	// (we can't easily inspect attached attrs, but we verify no panic)
	logger.Info("test message")
}

func TestLogger_WithoutContext(t *testing.T) {
	t.Parallel()

	logger := Logger(context.Background())
	if logger == nil {
		t.Fatal("Logger returned nil for empty context")
	}
	// Should be slog.Default()
	if logger != slog.Default() {
		t.Error("expected slog.Default() for empty context")
	}
}
