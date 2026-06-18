package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/observe"
)

// UsageInfo holds token usage extracted from SSE events.
type UsageInfo struct {
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
	SSEError                 bool
	SSEErrorData             string
	SSEErrorEarly            bool   // true if error occurred before any data was sent to client
	SSEErrorType             string // extracted error type (e.g., "rate_limit_error", "overloaded_error")
}

// sseEvent represents a single Server-Sent Event.
type sseEvent struct {
	Event string
	Data  string
}

// messageStartPayload mirrors the JSON structure of a message_start event.
type messageStartPayload struct {
	Message struct {
		Usage struct {
			InputTokens              int64 `json:"input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// messageDeltaPayload mirrors the JSON structure of a message_delta event.
type messageDeltaPayload struct {
	Usage struct {
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

// maxSSELineSize is the maximum size of a single SSE line.
// Claude thinking blocks can produce single lines exceeding 100KB.
const maxSSELineSize = 1 << 20 // 1MB

// sseBufPool reuses byte buffers for SSE event assembly to reduce allocations.
var sseBufPool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}

// ForwardSSE reads SSE events from upstream and writes them verbatim to downstream.
// It parses message_start and message_delta events to accumulate token usage.
// If an error event is detected as the FIRST event before any data, it returns early
// with SSEErrorEarly=true, signaling to the caller that the request should be retried.
// For errors after content has started, they are forwarded to the client.
// Forwarding stops when upstream is exhausted or ctx is cancelled.
func ForwardSSE(ctx context.Context, upstream io.Reader, downstream http.ResponseWriter, originalModel string) (*UsageInfo, error) {
	usage := &UsageInfo{}
	headersSent := false
	contentSent := false // track if we've written actual message content (not just meta)

	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSELineSize)

	flusher, canFlush := downstream.(http.Flusher)

	var currentEvent strings.Builder
	var currentData bytes.Buffer

	buf := sseBufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		sseBufPool.Put(buf)
	}()

	flushEvent := func() error {
		event := strings.TrimSpace(currentEvent.String())
		data := currentData.Bytes()
		data = bytes.TrimSpace(data)

		if event == "" && len(data) == 0 {
			return nil
		}

		// Parse usage and error status.
		switch event {
		case "message_start":
			var p messageStartPayload
			if err := json.Unmarshal(data, &p); err == nil {
				usage.InputTokens = p.Message.Usage.InputTokens
				usage.CacheCreationInputTokens = p.Message.Usage.CacheCreationInputTokens
				usage.CacheReadInputTokens = p.Message.Usage.CacheReadInputTokens
				observe.Logger(ctx).Debug("SSE: message_start usage",
					"input_tokens", p.Message.Usage.InputTokens,
					"cache_creation", p.Message.Usage.CacheCreationInputTokens,
					"cache_read", p.Message.Usage.CacheReadInputTokens,
				)
			}
			// Reverse-map model ID.
			if originalModel != "" {
				normalized := disguise.NormalizeModelID(originalModel)
				if normalized != originalModel {
					data = bytes.Replace(data, []byte(`"`+normalized+`"`), []byte(`"`+originalModel+`"`), 1)
					observe.Logger(ctx).Debug("SSE: model ID reverse-mapped",
						"from", normalized,
						"to", originalModel,
					)
				}
			}
			contentSent = true
			headersSent = true
		case "message_delta":
			var p messageDeltaPayload
			if err := json.Unmarshal(data, &p); err == nil {
				usage.OutputTokens = p.Usage.OutputTokens
				observe.Logger(ctx).Debug("SSE: message_delta usage",
					"output_tokens", p.Usage.OutputTokens,
				)
			}
			contentSent = true
			headersSent = true
		case "message_stop":
			// Metadata event, doesn't count as content
			headersSent = true
		case "error":
			// Extract error type from data.
			var errData map[string]interface{}
			if err := json.Unmarshal(data, &errData); err == nil {
				if errType, ok := errData["type"].(string); ok {
					usage.SSEErrorType = errType
				}
			}
			usage.SSEError = true
			usage.SSEErrorData = string(data)

			// If error is the first event before any content, mark as early.
			if !contentSent && !headersSent {
				usage.SSEErrorEarly = true
				observe.Logger(ctx).Warn("SSE: early error (no content sent)",
					"error_type", usage.SSEErrorType,
					"data", string(data))
				// Don't forward, return early so caller can retry
				currentEvent.Reset()
				currentData.Reset()
				return nil
			}

			observe.Logger(ctx).Warn("SSE: error after content",
				"error_type", usage.SSEErrorType,
				"data", string(data))
			// Error after content — must forward (can't change HTTP status now)
			headersSent = true
		}

		// Write to downstream
		buf.Reset()
		if event != "" {
			fmt.Fprintf(buf, "event: %s\n", event)
		}
		if len(data) > 0 {
			buf.WriteString("data: ")
			buf.Write(data)
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')

		if _, err := downstream.Write(buf.Bytes()); err != nil {
			currentEvent.Reset()
			currentData.Reset()
			return err
		}

		if canFlush {
			flusher.Flush()
		}

		currentEvent.Reset()
		currentData.Reset()
		return nil
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = flushEvent()
			return usage, nil
		default:
		}

		line := strings.TrimRight(scanner.Text(), "\r")

		switch {
		case strings.HasPrefix(line, "event:"):
			val := strings.TrimSpace(line[len("event:"):])
			currentEvent.Reset()
			currentEvent.WriteString(val)

		case strings.HasPrefix(line, "data:"):
			val := strings.TrimSpace(line[len("data:"):])
			// Per SSE spec, multiple data: lines in one event are concatenated with newlines.
			if currentData.Len() > 0 {
				currentData.WriteByte('\n')
			}
			currentData.WriteString(val)

		case line == "":
			// Empty line signals the end of an SSE event block.
			if err := flushEvent(); err != nil {
				return usage, nil // client disconnected, return collected usage
			}
		}
	}

	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return usage, nil
		}
		observe.Logger(ctx).Warn("SSE: scanner error",
			"error", err.Error(),
		)
		return usage, err
	}

	// Best-effort flush of any trailing event.
	_ = flushEvent()
	return usage, nil
}
