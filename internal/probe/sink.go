package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Capture is one intercepted outbound request recorded by the Sink.
type Capture struct {
	Body      []byte
	UserAgent string
	Host      string // the Host header the client sent (its view of the hostname)
	Path      string
}

// Sink is a local stand-in for the Anthropic API. It listens on loopback,
// records the outbound request body of every /v1/messages call, and returns a
// minimal well-formed response so the driven client (real `claude`) completes
// its request without error. It never contacts any upstream and never sees a
// real credential — the point is only to capture what the client *emits*.
type Sink struct {
	srv  *http.Server
	ln   net.Listener
	mu   sync.Mutex
	caps []Capture
}

// StartSink binds a listener on 127.0.0.1:port (port 0 picks a free port) and
// starts serving. Call Addr() for the chosen address and Close() when done.
func StartSink(port int) (*Sink, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	s := &Sink{ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", s.handleMessages)
	// Some client startup paths probe other endpoints; answer them benignly so
	// the client does not abort before it emits /v1/messages.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	s.srv = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Addr returns the sink's listen address, e.g. "127.0.0.1:54321".
func (s *Sink) Addr() string { return s.ln.Addr().String() }

// Port returns the sink's TCP port.
func (s *Sink) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Reset clears recorded captures. Call between variants so each variant's
// captures are isolated.
func (s *Sink) Reset() {
	s.mu.Lock()
	s.caps = nil
	s.mu.Unlock()
}

// Captures returns a copy of the currently recorded captures.
func (s *Sink) Captures() []Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Capture, len(s.caps))
	copy(out, s.caps)
	return out
}

// Close shuts the sink down.
func (s *Sink) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *Sink) handleMessages(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	_ = r.Body.Close()

	s.mu.Lock()
	s.caps = append(s.caps, Capture{
		Body:      body,
		UserAgent: r.Header.Get("User-Agent"),
		Host:      r.Host,
		Path:      r.URL.Path,
	})
	s.mu.Unlock()

	// Decide response shape from the request's stream flag.
	var hdr struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &hdr)

	if hdr.Stream {
		writeMinimalSSE(w)
		return
	}
	writeMinimalJSON(w)
}

// writeMinimalJSON returns the smallest well-formed non-stream Messages
// response the client will accept.
func writeMinimalJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"id":            "msg_probe",
		"type":          "message",
		"role":          "assistant",
		"model":         "probe",
		"content":       []map[string]any{{"type": "text", "text": "ok"}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage":         map[string]int{"input_tokens": 1, "output_tokens": 1},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// writeMinimalSSE returns the smallest well-formed streamed Messages response:
// message_start → content_block_start → content_block_delta → content_block_stop
// → message_delta → message_stop.
func writeMinimalSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	send := func(event string, data map[string]any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	send("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": "msg_probe", "type": "message", "role": "assistant",
			"model": "probe", "content": []any{}, "stop_reason": nil,
			"usage": map[string]int{"input_tokens": 1, "output_tokens": 0},
		},
	})
	send("content_block_start", map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{"type": "text", "text": ""},
	})
	send("content_block_delta", map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "text_delta", "text": "ok"},
	})
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": 1},
	})
	send("message_stop", map[string]any{"type": "message_stop"})
}
