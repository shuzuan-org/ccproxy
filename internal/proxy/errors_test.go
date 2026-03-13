package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/binn/ccproxy/internal/apierror"
)

func TestMapUpstreamError_401(t *testing.T) {
	status, body := MapUpstreamError(401, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502, got %d", status)
	}
	assertErrorBody(t, body, "authentication_error", "Upstream authentication failed")
}

func TestMapUpstreamError_403(t *testing.T) {
	status, body := MapUpstreamError(403, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502, got %d", status)
	}
	assertErrorBody(t, body, "forbidden_error", "Upstream access forbidden")
}

func TestMapUpstreamError_429_WithBody(t *testing.T) {
	upstream := []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"rate limited"}}`)
	status, body := MapUpstreamError(429, upstream)
	if status != 429 {
		t.Errorf("expected proxy status 429, got %d", status)
	}
	if string(body) != string(upstream) {
		t.Errorf("expected upstream body passthrough, got %s", body)
	}
}

func TestMapUpstreamError_429_EmptyBody(t *testing.T) {
	// Empty body falls through to generic 502
	status, _ := MapUpstreamError(429, nil)
	if status != 502 {
		t.Errorf("expected fallback status 502 for empty 429 body, got %d", status)
	}
}

func TestMapUpstreamError_529_WithBody(t *testing.T) {
	upstream := []byte(`{"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}`)
	status, body := MapUpstreamError(529, upstream)
	if status != 529 {
		t.Errorf("expected proxy status 529, got %d", status)
	}
	if string(body) != string(upstream) {
		t.Errorf("expected upstream body passthrough, got %s", body)
	}
}

func TestMapUpstreamError_400_WithBody(t *testing.T) {
	upstream := []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`)
	status, body := MapUpstreamError(400, upstream)
	if status != 400 {
		t.Errorf("expected proxy status 400, got %d", status)
	}
	if string(body) != string(upstream) {
		t.Errorf("expected upstream body passthrough, got %s", body)
	}
}

func TestMapUpstreamError_500(t *testing.T) {
	status, body := MapUpstreamError(500, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502, got %d", status)
	}
	assertErrorBody(t, body, "upstream_error", "Upstream service temporarily unavailable")
}

func TestMapUpstreamError_503(t *testing.T) {
	status, body := MapUpstreamError(503, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502, got %d", status)
	}
	assertErrorBody(t, body, "upstream_error", "Upstream service temporarily unavailable")
}

func TestMapUpstreamError_501(t *testing.T) {
	status, body := MapUpstreamError(501, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502 for 5xx, got %d", status)
	}
	assertErrorBody(t, body, "upstream_error", "Upstream service temporarily unavailable")
}

func TestMapUpstreamError_504(t *testing.T) {
	status, body := MapUpstreamError(504, nil)
	if status != 502 {
		t.Errorf("expected proxy status 502 for 504, got %d", status)
	}
	assertErrorBody(t, body, "upstream_error", "Upstream service temporarily unavailable")
}

func TestWriteError_ContentTypeAndBody(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteError(rr, http.StatusBadGateway, "authentication_error", "Upstream authentication failed")

	res := rr.Result()
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", res.StatusCode)
	}

	ct := res.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var ae apierror.Response
	if err := json.NewDecoder(res.Body).Decode(&ae); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if ae.Type != "error" {
		t.Errorf("expected top-level type 'error', got %q", ae.Type)
	}
	if ae.Error.Type != "authentication_error" {
		t.Errorf("expected error type 'authentication_error', got %q", ae.Error.Type)
	}
	if ae.Error.Message != "Upstream authentication failed" {
		t.Errorf("expected message 'Upstream authentication failed', got %q", ae.Error.Message)
	}
}

func TestWriteError_ValidJSON(t *testing.T) {
	cases := []struct {
		status  int
		errType string
		msg     string
	}{
		{429, "rate_limit_error", "Upstream rate limit exceeded"},
		{503, "overloaded_error", "Upstream service overloaded"},
		{502, "upstream_error", "Upstream service temporarily unavailable"},
	}

	for _, c := range cases {
		rr := httptest.NewRecorder()
		WriteError(rr, c.status, c.errType, c.msg)

		var ae apierror.Response
		if err := json.NewDecoder(rr.Result().Body).Decode(&ae); err != nil {
			t.Errorf("status=%d: invalid JSON: %v", c.status, err)
			continue
		}
		if ae.Type != "error" {
			t.Errorf("status=%d: expected type 'error', got %q", c.status, ae.Type)
		}
		if ae.Error.Type != c.errType {
			t.Errorf("status=%d: expected errType %q, got %q", c.status, c.errType, ae.Error.Type)
		}
		if ae.Error.Message != c.msg {
			t.Errorf("status=%d: expected msg %q, got %q", c.status, c.msg, ae.Error.Message)
		}
	}
}

// assertErrorBody decodes body into apierror.Response and checks errType and message.
func assertErrorBody(t *testing.T, body []byte, errType, message string) {
	t.Helper()
	var ae apierror.Response
	if err := json.Unmarshal(body, &ae); err != nil {
		t.Fatalf("failed to unmarshal body: %v (body: %s)", err, body)
	}
	if ae.Type != "error" {
		t.Errorf("expected top-level type 'error', got %q", ae.Type)
	}
	if ae.Error.Type != errType {
		t.Errorf("expected error type %q, got %q", errType, ae.Error.Type)
	}
	if ae.Error.Message != message {
		t.Errorf("expected message %q, got %q", message, ae.Error.Message)
	}
}
