package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

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

// sseBufPool reuses byte buffers for SSE event assembly to reduce allocations.
var sseBufPool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}

// ForwardSSE reads SSE events from upstream and writes them verbatim to downstream.
// It parses message_start and message_delta events to accumulate token usage.
// Forwarding stops when upstream is exhausted or ctx is cancelled.
func ForwardSSE(ctx context.Context, upstream io.Reader, downstream http.ResponseWriter, originalModel string) (*UsageInfo, error) {
	usage := &UsageInfo{}

	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSELineSize)

	// Pre-assert Flusher at entry instead of per-event type assertion
	flusher, canFlush := downstream.(http.Flusher)

	// Use []byte buffers to avoid string→[]byte conversion on Unmarshal
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

		// Parse usage from known event types before forwarding.
		switch event {
		case "message_start":
			var p messageStartPayload
			if err := json.Unmarshal(data, &p); err == nil {
				usage.InputTokens = p.Message.Usage.InputTokens
				usage.CacheCreationInputTokens = p.Message.Usage.CacheCreationInputTokens
				usage.CacheReadInputTokens = p.Message.Usage.CacheReadInputTokens
			}
			// Reverse-map model ID so downstream sees the original short name.
			if originalModel != "" {
				normalized := disguise.NormalizeModelID(originalModel)
				if normalized != originalModel {
					data = bytes.Replace(data, []byte(`"`+normalized+`"`), []byte(`"`+originalModel+`"`), 1)
				}
			}
		case "message_delta":
			var p messageDeltaPayload
			if err := json.Unmarshal(data, &p); err == nil {
				usage.OutputTokens = p.Usage.OutputTokens
			}
		case "error":
			usage.SSEError = true
			usage.SSEErrorData = string(data)
			slog.Warn("SSE error event received", "data", string(data))
		}

		// Merge 3 writes into 1 buffered write
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
