package apierror

import (
	"encoding/json"
	"net/http"
)

// Response represents an Anthropic API error response.
type Response struct {
	Type  string `json:"type"`
	Error Detail `json:"error"`
}

// Detail holds the error type and human-readable message.
type Detail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Write writes an Anthropic-style error response to w with the given HTTP
// status code, Anthropic error type, and message.
func Write(w http.ResponseWriter, statusCode int, errType, message string) {
	body, err := json.Marshal(Response{
		Type:  "error",
		Error: Detail{Type: errType, Message: message},
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"internal_error","message":"failed to encode error response"}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}
