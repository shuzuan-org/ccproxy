package apierror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite_Success(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	Write(w, http.StatusBadRequest, "invalid_request_error", "bad input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Type != "error" {
		t.Errorf("type = %q, want error", resp.Type)
	}
	if resp.Error.Type != "invalid_request_error" {
		t.Errorf("error.type = %q, want invalid_request_error", resp.Error.Type)
	}
	if resp.Error.Message != "bad input" {
		t.Errorf("error.message = %q, want 'bad input'", resp.Error.Message)
	}
}

func TestWrite_ErrorTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status  int
		errType string
		message string
	}{
		{http.StatusTooManyRequests, "rate_limit_error", "Too many requests"},
		{http.StatusUnauthorized, "authentication_error", "Invalid API key"},
		{http.StatusBadGateway, "overloaded_error", "Upstream overloaded"},
		{http.StatusInternalServerError, "api_error", "Internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.errType, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			Write(w, tc.status, tc.errType, tc.message)

			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Error.Type != tc.errType {
				t.Errorf("error.type = %q, want %q", resp.Error.Type, tc.errType)
			}
			if resp.Error.Message != tc.message {
				t.Errorf("error.message = %q, want %q", resp.Error.Message, tc.message)
			}
		})
	}
}

type brokenWriter struct {
	header     http.Header
	statusCode int
}

func (bw *brokenWriter) Header() http.Header      { return bw.header }
func (bw *brokenWriter) WriteHeader(code int)     { bw.statusCode = code }
func (bw *brokenWriter) Write([]byte) (int, error) { return 0, nil }

func TestWrite_WriterDoesNotPanic(t *testing.T) {
	t.Parallel()
	bw := &brokenWriter{header: make(http.Header)}
	Write(bw, http.StatusBadRequest, "invalid_request_error", "test")
	if bw.statusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", bw.statusCode, http.StatusBadRequest)
	}
}
