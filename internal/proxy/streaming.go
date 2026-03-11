package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/binn/ccproxy/internal/disguise"
)

// UsageInfo holds token usage extracted from SSE events.
type UsageInfo struct {
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
	SSEError                 bool
	SSEErrorData             string
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

// ForwardSSE reads SSE events from upstream and writes them verbatim to downstream.
// It parses message_start and message_delta events to accumulate token usage.
// Forwarding stops when upstream is exhausted or ctx is cancelled.
func ForwardSSE(ctx context.Context, upstream io.Reader, downstream http.ResponseWriter, originalModel string) (*UsageInfo, error) {
	usage := &UsageInfo{}

	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSELineSize)

	// Buffers for the current event being assembled.
	var currentEvent, currentData strings.Builder

	flushEvent := func() error {
		event := strings.TrimSpace(currentEvent.String())
		data := strings.TrimSpace(currentData.String())

		if event == "" && data == "" {
			return nil
		}

		// Parse usage from known event types before forwarding.
		switch event {
		case "message_start":
			var p messageStartPayload
			if err := json.Unmarshal([]byte(data), &p); err == nil {
				usage.InputTokens = p.Message.Usage.InputTokens
				usage.CacheCreationInputTokens = p.Message.Usage.CacheCreationInputTokens
				usage.CacheReadInputTokens = p.Message.Usage.CacheReadInputTokens
			}
			// Reverse-map model ID so downstream sees the original short name.
			if originalModel != "" {
				normalized := disguise.NormalizeModelID(originalModel)
				if normalized != originalModel {
					data = strings.Replace(data, `"`+normalized+`"`, `"`+originalModel+`"`, 1)
				}
			}
		case "message_delta":
			var p messageDeltaPayload
			if err := json.Unmarshal([]byte(data), &p); err == nil {
				usage.OutputTokens = p.Usage.OutputTokens
			}
		case "error":
			usage.SSEError = true
			usage.SSEErrorData = data
			slog.Warn("SSE error event received", "data", data)
		}

		// Forward the event verbatim to the downstream client.
		if event != "" {
			if _, err := fmt.Fprintf(downstream, "event: %s\n", event); err != nil {
				currentEvent.Reset()
				currentData.Reset()
				return err
			}
		}
		if data != "" {
			if _, err := fmt.Fprintf(downstream, "data: %s\n", data); err != nil {
				currentEvent.Reset()
				currentData.Reset()
				return err
			}
		}
		if _, err := fmt.Fprint(downstream, "\n"); err != nil {
			currentEvent.Reset()
			currentData.Reset()
			return err
		}

		// Flush immediately if the writer supports it.
		if f, ok := downstream.(http.Flusher); ok {
			f.Flush()
		}

		// Reset buffers for the next event.
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
			currentData.Reset()
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
		return usage, err
	}

	// Best-effort flush of any trailing event.
	_ = flushEvent()
	return usage, nil
}
