package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/binn/ccproxy/internal/config"
)

// successHandler returns 200 and writes the APIKeyName from context to the response body
func successHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := GetAuthInfo(r.Context())
		if !ok {
			http.Error(w, "no auth info", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(info.APIKeyName))
	})
}

func makeTestKeys() []config.APIKeyConfig {
	return []config.APIKeyConfig{
		{Key: "valid-key-one", Name: "key-one", Enabled: true},
		{Key: "valid-key-two", Name: "key-two", Enabled: true},
		{Key: "disabled-key", Name: "disabled", Enabled: false},
	}
}

func doRequest(t *testing.T, handler http.Handler, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestMissingAuthorizationHeader(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())
	rr := doRequest(t, handler, "")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("expected non-empty error body")
	}
}

func TestInvalidAuthorizationFormat(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())

	cases := []string{
		"valid-key-one",
		"Token valid-key-one",
		"bearer valid-key-one", // case sensitive
		"Basic dXNlcjpwYXNz",
	}

	for _, tc := range cases {
		rr := doRequest(t, handler, tc)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("header %q: expected 401, got %d", tc, rr.Code)
		}
	}
}

func TestEmptyBearerToken(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())
	// "Bearer " with nothing after it
	rr := doRequest(t, handler, "Bearer ")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestInvalidToken(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())
	rr := doRequest(t, handler, "Bearer wrong-key")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestValidToken(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())
	rr := doRequest(t, handler, "Bearer valid-key-one")

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "key-one" {
		t.Errorf("expected body %q, got %q", "key-one", string(body))
	}
}

func TestDisabledAPIKey(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())
	rr := doRequest(t, handler, "Bearer disabled-key")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled key, got %d", rr.Code)
	}
}

func TestMultipleAPIKeysCorrectOneMatches(t *testing.T) {
	handler := Middleware(makeTestKeys())(successHandler())

	// Test that the second key also works and returns its own name
	rr := doRequest(t, handler, "Bearer valid-key-two")

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	body, _ := io.ReadAll(rr.Body)
	if string(body) != "key-two" {
		t.Errorf("expected body %q, got %q", "key-two", string(body))
	}

	// Ensure the first key still matches independently
	rr2 := doRequest(t, handler, "Bearer valid-key-one")
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 for first key, got %d", rr2.Code)
	}
	body2, _ := io.ReadAll(rr2.Body)
	if string(body2) != "key-one" {
		t.Errorf("expected body %q, got %q", "key-one", string(body2))
	}
}

func TestAuthInfoInContext(t *testing.T) {
	var capturedInfo AuthInfo
	var capturedOk bool

	// Custom handler to capture context values
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedInfo, capturedOk = GetAuthInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(makeTestKeys())(captureHandler)
	doRequest(t, handler, "Bearer valid-key-one")

	if !capturedOk {
		t.Fatal("expected AuthInfo to be present in context")
	}
	if capturedInfo.APIKeyName != "key-one" {
		t.Errorf("expected APIKeyName %q, got %q", "key-one", capturedInfo.APIKeyName)
	}
}
