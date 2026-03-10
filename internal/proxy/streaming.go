package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// UsageInfo holds token usage extracted from SSE events.
type UsageInfo struct {
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
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

// ForwardSSE reads SSE events from upstream and writes them verbatim to downstream.
// It parses message_start and message_delta events to accumulate token usage.
// Forwarding stops when upstream is exhausted or ctx is cancelled.
func ForwardSSE(ctx context.Context, upstream io.Reader, downstream http.ResponseWriter) (*UsageInfo, error) {
	usage := &UsageInfo{}

	// Use a context-aware reader so slow upstreams respect cancellation.
	reader := bufio.NewReader(upstream)

	// Buffers for the current event being assembled.
	var currentEvent, currentData strings.Builder

	flushEvent := func() {
		event := strings.TrimSpace(currentEvent.String())
		data := strings.TrimSpace(currentData.String())

		if event == "" && data == "" {
			return
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
		case "message_delta":
			var p messageDeltaPayload
			if err := json.Unmarshal([]byte(data), &p); err == nil {
				usage.OutputTokens = p.Usage.OutputTokens
			}
		}

		// Forward the event verbatim to the downstream client.
		if event != "" {
			fmt.Fprintf(downstream, "event: %s\n", event)
		}
		if data != "" {
			fmt.Fprintf(downstream, "data: %s\n", data)
		}
		fmt.Fprint(downstream, "\n")

		// Flush immediately if the writer supports it.
		if f, ok := downstream.(http.Flusher); ok {
			f.Flush()
		}

		// Reset buffers for the next event.
		currentEvent.Reset()
		currentData.Reset()
	}

	for {
		// Check for context cancellation before each read.
		select {
		case <-ctx.Done():
			return usage, nil
		default:
		}

		line, err := reader.ReadString('\n')

		// Process whatever we read before handling the error.
		// Strip the trailing newline for easier comparison.
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(line, "event:"):
			// Trim the "event:" prefix and leading space.
			val := strings.TrimSpace(line[len("event:"):])
			currentEvent.Reset()
			currentEvent.WriteString(val)

		case strings.HasPrefix(line, "data:"):
			val := strings.TrimSpace(line[len("data:"):])
			currentData.Reset()
			currentData.WriteString(val)

		case line == "":
			// Empty line signals the end of an SSE event block.
			flushEvent()
		}

		if err != nil {
			if err == io.EOF {
				// Flush any trailing event that wasn't terminated by \n\n.
				flushEvent()
				return usage, nil
			}
			// Context cancellation surfaces as a pipe error from upstream.
			if ctx.Err() != nil {
				return usage, nil
			}
			return usage, err
		}
	}
}
