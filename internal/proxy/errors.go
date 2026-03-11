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
// corresponding proxy response parameters. Codes 400, 429, and 529 are
// intentionally absent — they are passed through with the original upstream body.
var upstreamErrorTable = map[int]errorMapping{
	401: {502, "authentication_error", "Upstream authentication failed"},
	403: {502, "forbidden_error", "Upstream access forbidden"},
}

// fallback5xxMapping is used for upstream 500-504 status codes not listed in
// upstreamErrorTable.
var fallback5xxMapping = errorMapping{
	proxyStatus: 502,
	errType:     "upstream_error",
	message:     "Upstream service temporarily unavailable",
}

// MapUpstreamError maps an upstream HTTP status code to a proxy status code
// and an Anthropic-format error response body. For client-visible error codes
// (400, 429, 529) the original upstream body is passed through so that the
// downstream client receives the exact error context from Anthropic. Internal
// auth errors (401, 403) and server errors (500-504) are sanitised to hide
// upstream details.
func MapUpstreamError(statusCode int, upstreamBody []byte) (int, []byte) {
	// Pass through client-visible errors with original body.
	switch statusCode {
	case 400, 429, 529:
		if len(upstreamBody) > 0 {
			return statusCode, upstreamBody
		}
		// Empty body fallback: synthesise a generic error.
	}

	if m, ok := upstreamErrorTable[statusCode]; ok {
		return buildResponse(m)
	}

	// Treat any remaining 5xx range (500-504) as a generic upstream error.
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
