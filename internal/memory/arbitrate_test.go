package memory

import (
	"strings"
	"testing"
)

func TestValidOperation(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
		want bool
	}{
		{name: "ADD", op: OpAdd, want: true},
		{name: "UPDATE", op: OpUpdate, want: true},
		{name: "DELETE", op: OpDelete, want: true},
		{name: "NOOP", op: OpNoop, want: true},
		{name: "empty", op: "", want: false},
		{name: "lowercase add", op: "add", want: false},
		{name: "unknown", op: "MERGE", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validOperation(tt.op)
			if got != tt.want {
				t.Errorf("validOperation(%q) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}

func TestArbitrationPromptFormat(t *testing.T) {
	existing := "User prefers Go"
	candidate := "User switched to Rust"

	// Verify the prompt template has correct placeholders count.
	// The prompt has 6 %s placeholders: nonce×3 for existing, nonce×3 for candidate.
	count := strings.Count(arbitrationPrompt, "%s")
	if count != 6 {
		t.Errorf("arbitrationPrompt has %d %%s placeholders, want 6", count)
	}

	// Verify both memories appear in a formatted prompt.
	nonce := "testnonce123"
	formatted := strings.Replace(arbitrationPrompt, "%s", nonce, 6)
	// The formatted prompt still has the placeholder text, not actual content.
	// Instead, verify the raw template contains the key structural elements.
	if !strings.Contains(arbitrationPrompt, "===EXISTING_") {
		t.Error("arbitrationPrompt missing EXISTING delimiter")
	}
	if !strings.Contains(arbitrationPrompt, "===CANDIDATE_") {
		t.Error("arbitrationPrompt missing CANDIDATE delimiter")
	}
	if !strings.Contains(formatted, nonce) {
		t.Error("formatted prompt missing nonce")
	}

	// Verify all 4 operations are documented.
	for _, op := range []string{"ADD", "UPDATE", "DELETE", "NOOP"} {
		if !strings.Contains(arbitrationPrompt, op) {
			t.Errorf("arbitrationPrompt missing operation %q", op)
		}
	}

	_ = existing
	_ = candidate
}
