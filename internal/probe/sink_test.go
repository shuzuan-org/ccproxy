package probe

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSink_CapturesBodyAndRespondsJSON(t *testing.T) {
	s, err := StartSink(0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	reqBody := `{"model":"x","stream":false,"system":"Today's date is 2026-07-01."}`
	resp, err := http.Post("http://"+s.Addr()+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(respBody, []byte(`"type":"message"`)) {
		t.Errorf("response not a minimal message: %s", respBody)
	}

	caps := s.Captures()
	if len(caps) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(caps))
	}
	if string(caps[0].Body) != reqBody {
		t.Errorf("captured body = %q, want %q", caps[0].Body, reqBody)
	}
}

func TestSink_RespondsSSEWhenStream(t *testing.T) {
	s, err := StartSink(0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	resp, err := http.Post("http://"+s.Addr()+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"x","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type = %q, want event-stream", ct)
	}
	for _, ev := range []string{"message_start", "content_block_delta", "message_stop"} {
		if !strings.Contains(string(body), "event: "+ev) {
			t.Errorf("SSE stream missing event %q; got:\n%s", ev, body)
		}
	}
}

func TestSink_ResetIsolatesCaptures(t *testing.T) {
	s, err := StartSink(0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	post := func() {
		r, _ := http.Post("http://"+s.Addr()+"/v1/messages", "application/json", strings.NewReader(`{"model":"x"}`))
		if r != nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
	}
	post()
	s.Reset()
	post()
	if n := len(s.Captures()); n != 1 {
		t.Fatalf("after reset expected 1 capture, got %d", n)
	}
}
