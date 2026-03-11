package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// responseRecorder wraps httptest.ResponseRecorder to capture streamed output.
type responseRecorder struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	written []string
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, string(b))
	return r.ResponseRecorder.Write(b)
}

func (r *responseRecorder) BodyString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Body.String()
}

// buildSSEStream constructs a raw SSE byte stream from event/data pairs.
func buildSSEStream(events []sseEvent) string {
	var sb strings.Builder
	for _, e := range events {
		if e.Event != "" {
			fmt.Fprintf(&sb, "event: %s\n", e.Event)
		}
		if e.Data != "" {
			fmt.Fprintf(&sb, "data: %s\n", e.Data)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// TestForwardSSE_BasicForwarding verifies all events are forwarded to downstream.
func TestForwardSSE_BasicForwarding(t *testing.T) {
	events := []sseEvent{
		{Event: "message_start", Data: `{"type":"message_start","message":{"usage":{"input_tokens":100,"cache_creation_input_tokens":0,"cache_read_input_tokens":50}}}`},
		{Event: "content_block_start", Data: `{"type":"content_block_start","index":0}`},
		{Event: "content_block_delta", Data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`},
		{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}`},
		{Event: "message_stop", Data: `{"type":"message_stop"}`},
	}

	raw := buildSSEStream(events)
	upstream := strings.NewReader(raw)
	w := newResponseRecorder()

	ctx := context.Background()
	usage, err := ForwardSSE(ctx, upstream, w, "")
	if err != nil {
		t.Fatalf("ForwardSSE returned error: %v", err)
	}

	body := w.BodyString()

	// Verify each event type appears in the forwarded output.
	for _, e := range events {
		if e.Event != "" {
			want := "event: " + e.Event
			if !strings.Contains(body, want) {
				t.Errorf("forwarded body missing %q; got:\n%s", want, body)
			}
		}
		if e.Data != "" {
			want := "data: " + e.Data
			if !strings.Contains(body, want) {
				t.Errorf("forwarded body missing data for event %q", e.Event)
			}
		}
	}

	// Verify usage extraction.
	if usage == nil {
		t.Fatal("expected non-nil UsageInfo")
	}
	if usage.InputTokens != 100 {
		t.Errorf("InputTokens = %d, want 100", usage.InputTokens)
	}
	if usage.OutputTokens != 42 {
		t.Errorf("OutputTokens = %d, want 42", usage.OutputTokens)
	}
	if usage.CacheReadInputTokens != 50 {
		t.Errorf("CacheReadInputTokens = %d, want 50", usage.CacheReadInputTokens)
	}
	if usage.CacheCreationInputTokens != 0 {
		t.Errorf("CacheCreationInputTokens = %d, want 0", usage.CacheCreationInputTokens)
	}
}

// TestForwardSSE_UsageExtraction verifies usage fields from both message_start and message_delta.
func TestForwardSSE_UsageExtraction(t *testing.T) {
	events := []sseEvent{
		{
			Event: "message_start",
			Data:  `{"type":"message_start","message":{"usage":{"input_tokens":200,"cache_creation_input_tokens":10,"cache_read_input_tokens":30}}}`,
		},
		{
			Event: "message_delta",
			Data:  `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":99}}`,
		},
	}

	raw := buildSSEStream(events)
	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), newResponseRecorder(), "")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}
	if usage == nil {
		t.Fatal("expected non-nil UsageInfo")
	}
	if usage.InputTokens != 200 {
		t.Errorf("InputTokens = %d, want 200", usage.InputTokens)
	}
	if usage.OutputTokens != 99 {
		t.Errorf("OutputTokens = %d, want 99", usage.OutputTokens)
	}
	if usage.CacheCreationInputTokens != 10 {
		t.Errorf("CacheCreationInputTokens = %d, want 10", usage.CacheCreationInputTokens)
	}
	if usage.CacheReadInputTokens != 30 {
		t.Errorf("CacheReadInputTokens = %d, want 30", usage.CacheReadInputTokens)
	}
}

// TestForwardSSE_ContextCancellation verifies that a cancelled context stops forwarding.
func TestForwardSSE_ContextCancellation(t *testing.T) {
	// Use a slow pipe so we can cancel mid-stream.
	pr, pw := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	w := newResponseRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ForwardSSE(ctx, pr, w, "") //nolint:errcheck
	}()

	// Write one event then cancel.
	_, _ = fmt.Fprint(pw, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
	time.Sleep(20 * time.Millisecond)
	cancel()
	// Close writer so ForwardSSE's reader eventually unblocks.
	pw.CloseWithError(context.Canceled)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good — ForwardSSE returned after cancellation.
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardSSE did not stop after context cancellation within 2s")
	}
}

// TestForwardSSE_IncompleteChunks verifies parsing works when data arrives in small pieces.
func TestForwardSSE_IncompleteChunks(t *testing.T) {
	// Simulate slow/chunked delivery via a pipe.
	pr, pw := io.Pipe()

	w := newResponseRecorder()
	var (
		usage *UsageInfo
		fwErr error
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		usage, fwErr = ForwardSSE(context.Background(), pr, w, "")
	}()

	// Send bytes in tiny pieces.
	chunks := []string{
		"event: mess",
		"age_start\n",
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,",
		"\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0}}}\n",
		"\n", // terminates the event
		"event: message_delta\n",
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n",
		"\n",
	}
	for _, chunk := range chunks {
		_, err := fmt.Fprint(pw, chunk)
		if err != nil {
			t.Fatalf("write chunk error: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = pw.Close()

	wg.Wait()

	if fwErr != nil {
		t.Fatalf("ForwardSSE error: %v", fwErr)
	}
	if usage == nil {
		t.Fatal("expected non-nil UsageInfo")
	}
	if usage.InputTokens != 5 {
		t.Errorf("InputTokens = %d, want 5", usage.InputTokens)
	}
	if usage.OutputTokens != 7 {
		t.Errorf("OutputTokens = %d, want 7", usage.OutputTokens)
	}
}

// TestForwardSSE_EmptyStream verifies that an empty upstream returns nil usage without error.
func TestForwardSSE_EmptyStream(t *testing.T) {
	usage, err := ForwardSSE(context.Background(), strings.NewReader(""), newResponseRecorder(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage == nil {
		t.Fatal("expected non-nil UsageInfo even for empty stream")
	}
}

// TestForwardSSE_NoUsageEvents verifies zero usage when no message_start/delta events arrive.
func TestForwardSSE_NoUsageEvents(t *testing.T) {
	events := []sseEvent{
		{Event: "ping", Data: `{}`},
	}
	raw := buildSSEStream(events)
	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), newResponseRecorder(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Errorf("expected zero usage, got %+v", usage)
	}
}

// TestForwardSSE_RealHTTPServer runs ForwardSSE against a real HTTP SSE server.
func TestForwardSSE_RealHTTPServer(t *testing.T) {
	sseBody := buildSSEStream([]sseEvent{
		{Event: "message_start", Data: `{"type":"message_start","message":{"usage":{"input_tokens":10,"cache_creation_input_tokens":2,"cache_read_input_tokens":3}}}`},
		{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`},
		{Event: "message_stop", Data: `{"type":"message_stop"}`},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, sseBody)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	w := newResponseRecorder()
	usage, err := ForwardSSE(context.Background(), resp.Body, w, "")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	if usage.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 5 {
		t.Errorf("OutputTokens = %d, want 5", usage.OutputTokens)
	}
	if usage.CacheCreationInputTokens != 2 {
		t.Errorf("CacheCreationInputTokens = %d, want 2", usage.CacheCreationInputTokens)
	}
	if usage.CacheReadInputTokens != 3 {
		t.Errorf("CacheReadInputTokens = %d, want 3", usage.CacheReadInputTokens)
	}
}

// TestForwardSSE_EventOrdering verifies events are forwarded in the same order as received.
func TestForwardSSE_EventOrdering(t *testing.T) {
	eventNames := []string{"message_start", "content_block_start", "content_block_delta", "message_delta", "message_stop"}
	var events []sseEvent
	for _, name := range eventNames {
		events = append(events, sseEvent{Event: name, Data: `{}`})
	}

	raw := buildSSEStream(events)
	w := newResponseRecorder()
	_, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	body := w.BodyString()
	lastIdx := -1
	for _, name := range eventNames {
		idx := strings.Index(body, "event: "+name)
		if idx == -1 {
			t.Errorf("event %q not found in output", name)
			continue
		}
		if idx <= lastIdx {
			t.Errorf("event %q appears out of order in output", name)
		}
		lastIdx = idx
	}
}

// TestForwardSSE_LargeThinkingBlock verifies that a 200KB data line is not truncated.
func TestForwardSSE_LargeThinkingBlock(t *testing.T) {
	t.Parallel()

	// Build a ~200KB thinking text payload.
	largeText := strings.Repeat("x", 200*1024)
	data := fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"%s"}}`, largeText)

	events := []sseEvent{
		{Event: "message_start", Data: `{"type":"message_start","message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`},
		{Event: "content_block_delta", Data: data},
		{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`},
	}

	raw := buildSSEStream(events)
	w := newResponseRecorder()
	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	body := w.BodyString()

	// Verify the large data line was forwarded completely.
	if !strings.Contains(body, largeText) {
		t.Errorf("large thinking block was truncated: body length = %d, expected to contain %d chars of 'x'", len(body), len(largeText))
	}

	if usage.InputTokens != 1 {
		t.Errorf("InputTokens = %d, want 1", usage.InputTokens)
	}
}

// TestForwardSSE_ModelDenormalization verifies model ID is reversed in message_start.
func TestForwardSSE_ModelDenormalization(t *testing.T) {
	t.Parallel()

	events := []sseEvent{
		{
			Event: "message_start",
			Data:  `{"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`,
		},
		{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`},
	}

	raw := buildSSEStream(events)
	w := newResponseRecorder()
	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "claude-sonnet-4-5")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	body := w.BodyString()

	// Should contain the short model name, not the versioned one.
	if !strings.Contains(body, `"claude-sonnet-4-5"`) {
		t.Errorf("expected short model name in output, got:\n%s", body)
	}
	if strings.Contains(body, `"claude-sonnet-4-5-20250929"`) {
		t.Errorf("versioned model name should have been replaced, got:\n%s", body)
	}

	if usage.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10", usage.InputTokens)
	}
}

// TestForwardSSE_ModelDenormalization_NoOp verifies no replacement when model is already short.
func TestForwardSSE_ModelDenormalization_NoOp(t *testing.T) {
	t.Parallel()

	events := []sseEvent{
		{
			Event: "message_start",
			Data:  `{"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`,
		},
	}

	raw := buildSSEStream(events)
	w := newResponseRecorder()
	// Pass the already-versioned name — NormalizeModelID returns itself, so no replacement.
	_, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "claude-sonnet-4-5-20250929")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	body := w.BodyString()
	if !strings.Contains(body, `"claude-sonnet-4-5-20250929"`) {
		t.Errorf("versioned model name should remain unchanged, got:\n%s", body)
	}
}

// errorAfterNWriter is a ResponseWriter that returns an error after n writes.
type errorAfterNWriter struct {
	*httptest.ResponseRecorder
	remaining int
}

func (w *errorAfterNWriter) Write(b []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, fmt.Errorf("simulated client disconnect")
	}
	w.remaining--
	return w.ResponseRecorder.Write(b)
}

// TestForwardSSE_ClientDisconnect verifies ForwardSSE returns cleanly on write error.
func TestForwardSSE_ClientDisconnect(t *testing.T) {
	t.Parallel()

	events := []sseEvent{
		{Event: "message_start", Data: `{"type":"message_start","message":{"usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`},
		{Event: "content_block_delta", Data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`},
		{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`},
	}

	raw := buildSSEStream(events)

	// Allow first event's writes (event + data + newline = 3 writes), fail on second event.
	w := &errorAfterNWriter{
		ResponseRecorder: httptest.NewRecorder(),
		remaining:        3,
	}

	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "")
	if err != nil {
		t.Fatalf("expected nil error on client disconnect, got: %v", err)
	}

	// Should have collected usage from the first event (message_start).
	if usage.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10", usage.InputTokens)
	}
}

// TestForwardSSE_ErrorEvent verifies error events are detected and still forwarded.
func TestForwardSSE_ErrorEvent(t *testing.T) {
	t.Parallel()

	errData := `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`
	events := []sseEvent{
		{Event: "message_start", Data: `{"type":"message_start","message":{"usage":{"input_tokens":5,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`},
		{Event: "error", Data: errData},
	}

	raw := buildSSEStream(events)
	w := newResponseRecorder()
	usage, err := ForwardSSE(context.Background(), strings.NewReader(raw), w, "")
	if err != nil {
		t.Fatalf("ForwardSSE error: %v", err)
	}

	if !usage.SSEError {
		t.Error("expected SSEError=true")
	}
	if usage.SSEErrorData != errData {
		t.Errorf("SSEErrorData = %q, want %q", usage.SSEErrorData, errData)
	}

	// Verify the error event was still forwarded to downstream.
	body := w.BodyString()
	if !strings.Contains(body, "event: error") {
		t.Error("error event not forwarded to downstream")
	}
	if !strings.Contains(body, errData) {
		t.Error("error event data not forwarded to downstream")
	}
}
