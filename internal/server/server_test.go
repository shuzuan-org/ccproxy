package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := recoveryMiddleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRecoveryMiddleware_WithPanic(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})
	handler := recoveryMiddleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	// recoveryMiddleware checks w.(*loggingResponseWriter) — wrap it so the 500 is written
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	handler.ServeHTTP(lrw, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestBasicAuth_Correct(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestBasicAuth_Wrong(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestBasicAuth_NoAuth(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestLoggingResponseWriter_CapturesStatus(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	lrw.WriteHeader(http.StatusNotFound)

	if lrw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want 404", lrw.statusCode)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("underlying status = %d, want 404", w.Code)
	}
}

func TestLoggingResponseWriter_Flush(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	// Should not panic — httptest.ResponseRecorder supports Flush
	lrw.Flush()
	if !w.Flushed {
		t.Error("expected underlying writer to be flushed")
	}
}

func TestRequestLogMiddleware(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requestLogMiddleware(inner)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
