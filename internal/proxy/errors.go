package proxy

import (
	"encoding/json"
	"net/http"
)

// AnthropicError represents an Anthropic API error response.
type AnthropicError struct {
	Type  string               `json:"type"`
	Error AnthropicErrorDetail `json:"error"`
}

// AnthropicErrorDetail holds the error type and human-readable message.
type AnthropicErrorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// errorMapping defines a mapping from an upstream status code to a proxy
// status code, an Anthropic error type string, and a message.
type errorMapping struct {
	proxyStatus int
	errType     string
	message     string
}

// upstreamErrorTable maps specific upstream HTTP status codes to their
// corresponding proxy response parameters.
var upstreamErrorTable = map[int]errorMapping{
	401: {502, "authentication_error", "Upstream authentication failed"},
	403: {502, "forbidden_error", "Upstream access forbidden"},
	429: {429, "rate_limit_error", "Upstream rate limit exceeded"},
	529: {503, "overloaded_error", "Upstream service overloaded"},
}

// fallback5xxMapping is used for upstream 500-504 status codes not listed in
// upstreamErrorTable.
var fallback5xxMapping = errorMapping{
	proxyStatus: 502,
	errType:     "upstream_error",
	message:     "Upstream service temporarily unavailable",
}

// MapUpstreamError maps an upstream HTTP status code to a proxy status code
// and an Anthropic-format error response body. upstreamBody is accepted for
// future use but is currently unused — the proxy always synthesises its own
// error message so that internal upstream details are never leaked to clients.
func MapUpstreamError(statusCode int, upstreamBody []byte) (int, []byte) {
	if m, ok := upstreamErrorTable[statusCode]; ok {
		return buildResponse(m)
	}

	// Treat any remaining 5xx range (500-504, excluding 529 already handled)
	// as a generic upstream error.
	if statusCode >= 500 && statusCode <= 504 {
		return buildResponse(fallback5xxMapping)
	}

	// Fallback for any other unexpected status: surface as a generic 502.
	return buildResponse(fallback5xxMapping)
}

// buildResponse serialises an errorMapping into a proxy status code and JSON
// body. Panics are intentionally not recovered here — a marshal failure on a
// static struct is a programming error and should surface loudly.
func buildResponse(m errorMapping) (int, []byte) {
	ae := AnthropicError{
		Type: "error",
		Error: AnthropicErrorDetail{
			Type:    m.errType,
			Message: m.message,
		},
	}
	body, err := json.Marshal(ae)
	if err != nil {
		// Static struct — this should never happen.
		panic("proxy: failed to marshal AnthropicError: " + err.Error())
	}
	return m.proxyStatus, body
}

// WriteError writes an Anthropic-style error response to w with the given HTTP
// status code, Anthropic error type, and message.
func WriteError(w http.ResponseWriter, statusCode int, errType, message string) {
	ae := AnthropicError{
		Type: "error",
		Error: AnthropicErrorDetail{
			Type:    errType,
			Message: message,
		},
	}
	body, err := json.Marshal(ae)
	if err != nil {
		// Fall back to a minimal hard-coded response to avoid a silent failure.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"internal_error","message":"failed to encode error response"}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}
