package disguise

// ModelIDOverrides maps short model names to full versioned names.
// OAuth accounts require full versioned model IDs.
var ModelIDOverrides = map[string]string{
	"claude-sonnet-4-5": "claude-sonnet-4-5-20250929",
	"claude-opus-4-5":   "claude-opus-4-5-20251101",
	"claude-haiku-4-5":  "claude-haiku-4-5-20251001",
}

// ModelIDReverseOverrides maps full versioned names back to short names.
var ModelIDReverseOverrides = map[string]string{
	"claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
	"claude-opus-4-5-20251101":   "claude-opus-4-5",
	"claude-haiku-4-5-20251001":  "claude-haiku-4-5",
}

// NormalizeModelID converts a short model name to full versioned name.
// Unknown models pass through unchanged.
func NormalizeModelID(id string) string {
	if full, ok := ModelIDOverrides[id]; ok {
		return full
	}
	return id
}

// DenormalizeModelID converts a full versioned model name back to short name.
// Unknown models pass through unchanged.
func DenormalizeModelID(id string) string {
	if short, ok := ModelIDReverseOverrides[id]; ok {
		return short
	}
	return id
}
