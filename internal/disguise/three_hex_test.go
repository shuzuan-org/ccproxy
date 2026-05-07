package disguise

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsMetaText(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"<system-reminder>\nSome injected reminder", true},
		{"  <system-reminder>...", true}, // leading whitespace tolerated
		{"<local-command-caveat>Caveat:", true},
		{"<command-name>/clear</command-name>", true},
		{"Result of calling the Read tool:\nfile contents", true},
		{"Called the Bash tool with the following input: ls", true},
		{"## Exited Plan Mode\n\nYou have exited", true},
		{"## Exited Auto Mode\n\nThe user", true},
		{"Continue from where you left off.", true},
		{"This session is being continued from another machine.", true},
		{"The date has changed. Today is now ...", true},
		{"<mcp-resource server=foo>", true},

		// Real user inputs — must NOT match
		{"say hi", false},
		{"Deep code review of the package", false},
		{"Implement the feature please", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			got := isMetaText(tc.text)
			if got != tc.want {
				t.Errorf("isMetaText(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

func TestFirstNonMetaUserText_FreshSample(t *testing.T) {
	// fresh_sample.bin: 4-block user message, blocks 0..2 are
	// system-reminder wrappers, block 3 is the real "say hi".
	path := filepath.Join("..", "..", "mitm-analysis", "cch-probe", "fresh_sample.bin")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ground-truth sample missing: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	messages, _ := parsed["messages"].([]interface{})
	got := firstNonMetaUserText(messages)
	if got != "say hi" {
		t.Errorf("firstNonMetaUserText = %q, want %q", got, "say hi")
	}
}

func TestCompute3HexSuffix_FreshSample(t *testing.T) {
	// Real Claude Code 2.1.126 request → cc_version=2.1.126.125
	path := filepath.Join("..", "..", "mitm-analysis", "cch-probe", "fresh_sample.bin")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ground-truth sample missing: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	messages, _ := parsed["messages"].([]interface{})
	got := Compute3HexSuffix("2.1.126", messages)
	if got != "125" {
		t.Errorf("Compute3HexSuffix = %q, want %q", got, "125")
	}
}

func TestCompute3HexSuffix_StringContent(t *testing.T) {
	// content as plain string (older Anthropic schema), not array
	messages := []interface{}{
		map[string]interface{}{
			"role":    "user",
			"content": "say hi",
		},
	}
	// Same input as fresh_sample.bin's resolved text → same 3hex
	got := Compute3HexSuffix("2.1.126", messages)
	if got != "125" {
		t.Errorf("Compute3HexSuffix(string content) = %q, want %q", got, "125")
	}
}

func TestCompute3HexSuffix_AllMetaFallsThrough(t *testing.T) {
	// All user blocks are meta wrappers — vM3 returns "" → chars="000"
	messages := []interface{}{
		map[string]interface{}{
			"role": "user",
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "<system-reminder>only system context</system-reminder>",
				},
			},
		},
	}
	got := Compute3HexSuffix("2.1.126", messages)
	if got == "" || len(got) != 3 {
		t.Errorf("Compute3HexSuffix returned malformed value %q", got)
	}
	// The exact value isn't asserted — it just needs to be consistent
	// with the algorithm. What matters is no crash and 3-char output.
}

func TestCompute3HexSuffix_ShortText(t *testing.T) {
	// 2-char user message: chars[4], [7], [20] all default to '0'.
	// chars = "000".
	messages := []interface{}{
		map[string]interface{}{
			"role":    "user",
			"content": "hi",
		},
	}
	got := Compute3HexSuffix("2.1.126", messages)
	// Hand-computed: sha256("59cf53e54c78" + "000" + "2.1.126")[:3] → "88c"
	if got != "88c" {
		t.Errorf("Compute3HexSuffix(short text) = %q, want %q", got, "88c")
	}
}
