# Design: Disguise Chain Alignment with sub2api

**Date:** 2026-03-30
**Scope:** `internal/disguise/`, `internal/proxy/bodyfilter.go`
**Approach:** A — in-place augmentation of existing files

## Background

ccproxy and sub2api share the same disguise goal: impersonating the Claude CLI to upstream Anthropic endpoints. A cross-codebase audit identified three gaps where ccproxy diverges from sub2api's current behavior. This document specifies the alignment changes.

Items already verified as aligned:
- TLS fingerprint (aligned in commit `7a57ca9`)
- HTTP header wire order (sub2api uses it only for debug logging — not enforced on the wire)
- Thinking block retry logic (ccproxy has equivalent logic in `bodyfilter.go`)

---

## Gap 1: metadata.user_id — New JSON Format (CLI ≥ 2.1.78)

### Problem

Claude CLI ≥ 2.1.78 changed `metadata.user_id` from a string to a JSON object:

```json
{"device_id":"abc...ef","account_uuid":"550e8400-...","session_id":"550e8400-..."}
```

ccproxy only recognizes and generates the old string format:
```
user_{64hex}_account__session_{uuid}
```

When a CLI ≥ 2.1.78 client sends the JSON format, ccproxy's `ParseUserID` fails to parse it, causing the user_id signal to score 0 in the CC detector — potentially misclassifying legitimate CC clients as non-CC clients.

### Design

**`internal/disguise/metadata.go`**

1. Add constant: `NewMetadataFormatMinVersion = "2.1.78"`

2. Add struct:
   ```go
   type userIDJSON struct {
       DeviceID    string `json:"device_id"`
       AccountUUID string `json:"account_uuid,omitempty"`
       SessionID   string `json:"session_id"`
   }
   ```

3. Extend `ParseUserID()`: attempt JSON unmarshal first; if the input starts with `{`, try JSON decode; fall back to existing regex parsing. Return a unified internal representation with fields `DeviceID`, `AccountUUID`, `SessionID`, `IsNewFormat bool`.

4. Extend `GenerateUserID(sessionSeed, uaVersion string)`: if `uaVersion >= "2.1.78"` (semver compare), marshal as JSON; otherwise use existing string format.

5. Extend `RewriteUserIDWithMasking(originalUserID, sessionSeed, maskedSessionUUID, uaVersion string)`: detect input format via `ParseUserID`; output the same format as input (JSON in → JSON out, string in → string out).

**`internal/disguise/engine.go`**

6. Extract UA version in `Apply()`:
   - Parse `origReq.Header.Get("User-Agent")` with regex `^claude-cli/(\d+\.\d+\.\d+)` to get `uaVersion`; default to `""` if absent.
   - Pass `uaVersion` to `GenerateUserID` (non-CC path) and `RewriteUserIDWithMasking` (CC path).

**Detector (`internal/disguise/detector.go`)**

7. Update the user_id signal check: the existing regex `^user_[a-fA-F0-9]{64}_account_...` does **not** match the JSON format `{"device_id":"..."}`. Change the signal 3 check to call `ParseUserID()` (which handles both formats) instead of applying the raw regex directly. Signal 3 scores 1 if `ParseUserID()` returns a non-nil result with non-empty `DeviceID` and `SessionID`.

---

## Gap 2: Empty Text Blocks After Thinking Conversion

### Problem

`filterThinkingFromContent()` converts `thinking` → `text` blocks. If the thinking content is `""`, this produces `{"type":"text","text":""}`. Anthropic rejects empty text blocks with a 400 error: `"text content blocks must be non-empty"`.

### Design

**`internal/proxy/bodyfilter.go`**

1. In `filterThinkingFromContent()`: when converting `thinking` → `text`, if the resulting `text == ""`, skip appending the block entirely (do not create an empty text block). The existing empty-array fallback (`"(content removed)"`) handles the case where all blocks are filtered.

2. Add `stripEmptyTextBlocks(content []any) []any`: removes any block where `type == "text"` and `text == ""`. This covers empty text blocks that arrive in the original request (not just from thinking conversion).

3. In `filterBlocks()`: after applying `contentFilter` to each message's content, call `stripEmptyTextBlocks()` on the result.

4. Preserve: the existing `len(result) == 0` placeholder guard — empty-array protection remains in place.

---

## Gap 3: System Prompt Prefix List Sync

### Problem

`claudeCodePromptPrefixes` in `detector.go` has 8 entries; sub2api's reference list has 6. Two differences:

- ccproxy prefix #4 truncates the "file search specialist" prompt: `"You are a file search specialist for Claude Code"` — sub2api has the full form: `"You are a file search specialist for Claude Code, Anthropic's official CLI for Claude."`
- ccproxy has an extra entry `"You are an agent for Claude Code"` not in sub2api

The prefix list is used for both:
1. CC client detection (signal 4 in the scorer)
2. Injection dedup check in `injectSystemPromptInPlace`

### Design

**`internal/disguise/detector.go`**

Update `claudeCodePromptPrefixes` to:

```go
var claudeCodePromptPrefixes = []string{
    "You are Claude Code, Anthropic's official CLI for Claude",
    "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.",
    "You are a Claude agent, built on Anthropic's Claude Agent SDK",
    "You are a file search specialist for Claude Code, Anthropic's official CLI for Claude.",
    "You are a helpful AI assistant tasked with summarizing conversations",
    "You are an agent for Claude Code",
    "You are an interactive CLI tool that helps users",
    "You are Claude, made by Anthropic",
}
```

Changes from current:
- Entry 4: extend from truncated form to full form (adds `, Anthropic's official CLI for Claude.`)
- Retain `"You are an agent for Claude Code"` and `"You are Claude, made by Anthropic"` — ccproxy-specific variants, no harm in keeping them

No change to `injectSystemPromptInPlace` — it references the same list and the dedup logic is unaffected.

---

## Files Modified

| File | Change |
|------|--------|
| `internal/disguise/metadata.go` | JSON format support, version-aware generation |
| `internal/disguise/engine.go` | Extract and pass UA version |
| `internal/proxy/bodyfilter.go` | Strip empty text blocks post-conversion |
| `internal/disguise/detector.go` | Update user_id signal to use `ParseUserID()` + sync prefix list entry #4 |

## Files NOT Modified

| File | Reason |
|------|--------|
| `internal/tls/fingerprint.go` | Already aligned |
| `internal/disguise/beta.go` | Already aligned |
| `internal/disguise/headers.go` | Already aligned |
| `internal/disguise/thinking.go` | Disguise-layer cache_control cleanup — separate concern from retry-layer filtering |

---

## Testing

Each change maps to an existing test file:

- `metadata_test.go`: add table rows for JSON format parsing, generation (version < and >= 2.1.78), and round-trip rewrite
- `bodyfilter_test.go` (or `bodyfilter_test.go` if exists): add cases for empty-text-block stripping
- `detector_test.go`: verify updated prefix #4 still scores signal 4 correctly
- `engine_test.go`: add case where CC client sends JSON-format user_id and verify it is rewritten correctly
