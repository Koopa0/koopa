package chat

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/session"
)

// TestConfig_validate tests that each validation check in Config.validate()
// fires independently. Each case provides enough deps to pass prior checks.
func TestConfig_validate(t *testing.T) {
	t.Parallel()

	// Minimal non-nil stubs — validate() only checks nil, never dereferences.
	stubG := new(genkit.Genkit)
	stubS := new(session.Store)
	stubL := slog.New(slog.DiscardHandler)

	tests := []struct {
		name        string
		cfg         Config
		errContains string
	}{
		{
			name:        "nil genkit",
			cfg:         Config{},
			errContains: "genkit instance is required",
		},
		{
			name: "nil session store",
			cfg: Config{
				Genkit: stubG,
			},
			errContains: "session store is required",
		},
		{
			name: "nil logger",
			cfg: Config{
				Genkit:       stubG,
				SessionStore: stubS,
			},
			errContains: "logger is required",
		},
		{
			name: "empty tools",
			cfg: Config{
				Genkit:       stubG,
				SessionStore: stubS,
				Logger:       stubL,
				Tools:        []ai.Tool{},
			},
			errContains: "at least one tool is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.validate()
			if err == nil {
				t.Fatal("validate() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("validate() error = %q, want to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestDeepCopyMessages_NilInput(t *testing.T) {
	t.Parallel()
	got := deepCopyMessages(nil)
	if got != nil {
		t.Errorf("deepCopyMessages(nil) = %v, want nil", got)
	}
}

func TestDeepCopyMessages_EmptySlice(t *testing.T) {
	t.Parallel()
	got := deepCopyMessages([]*ai.Message{})
	if got == nil {
		t.Fatal("deepCopyMessages(empty) = nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("deepCopyMessages(empty) len = %d, want 0", len(got))
	}
}

func TestDeepCopyMessages_MutateOriginalText(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("hello world")),
	}

	copied := deepCopyMessages(original)

	// Mutate the original message's content slice
	original[0].Content[0].Text = "MUTATED"

	if copied[0].Content[0].Text != "hello world" {
		t.Errorf("deepCopyMessages() copy was affected by original mutation: got %q, want %q",
			copied[0].Content[0].Text, "hello world")
	}
}

func TestDeepCopyMessages_MutateOriginalContentSlice(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("first"), ai.NewTextPart("second")),
	}

	copied := deepCopyMessages(original)

	// Append to original's content slice — should not affect copy
	original[0].Content = append(original[0].Content, ai.NewTextPart("third"))

	if len(copied[0].Content) != 2 {
		t.Errorf("deepCopyMessages() copy content len = %d, want 2", len(copied[0].Content))
	}
}

func TestDeepCopyMessages_PreservesRole(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("q")),
		ai.NewModelMessage(ai.NewTextPart("a")),
	}

	copied := deepCopyMessages(original)

	if copied[0].Role != ai.RoleUser {
		t.Errorf("deepCopyMessages()[0].Role = %q, want %q", copied[0].Role, ai.RoleUser)
	}
	if copied[1].Role != ai.RoleModel {
		t.Errorf("deepCopyMessages()[1].Role = %q, want %q", copied[1].Role, ai.RoleModel)
	}
}

func TestDeepCopyMessages_Metadata(t *testing.T) {
	t.Parallel()

	original := []*ai.Message{{
		Role:     ai.RoleUser,
		Content:  []*ai.Part{ai.NewTextPart("test")},
		Metadata: map[string]any{"key": "value"},
	}}

	copied := deepCopyMessages(original)

	// Mutate original metadata
	original[0].Metadata["key"] = "MUTATED"

	if copied[0].Metadata["key"] != "value" {
		t.Errorf("deepCopyMessages() metadata was affected by mutation: got %q, want %q",
			copied[0].Metadata["key"], "value")
	}
}

func TestDeepCopyPart_NilInput(t *testing.T) {
	t.Parallel()
	got := deepCopyPart(nil)
	if got != nil {
		t.Errorf("deepCopyPart(nil) = %v, want nil", got)
	}
}

func TestDeepCopyPart_TextPart(t *testing.T) {
	t.Parallel()

	original := ai.NewTextPart("hello")
	copied := deepCopyPart(original)

	original.Text = "MUTATED"

	if copied.Text != "hello" {
		t.Errorf("deepCopyPart() text affected by mutation: got %q, want %q", copied.Text, "hello")
	}
}

func TestDeepCopyPart_ToolRequest(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind: ai.PartToolRequest,
		ToolRequest: &ai.ToolRequest{
			Name:  "read_file",
			Input: map[string]any{"path": "/tmp/test"},
		},
	}

	copied := deepCopyPart(original)

	// Mutate original ToolRequest name
	original.ToolRequest.Name = "MUTATED"

	if copied.ToolRequest.Name != "read_file" {
		t.Errorf("deepCopyPart() ToolRequest.Name affected by mutation: got %q, want %q",
			copied.ToolRequest.Name, "read_file")
	}
}

func TestDeepCopyPart_ToolResponse(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind: ai.PartToolResponse,
		ToolResponse: &ai.ToolResponse{
			Name:   "read_file",
			Output: "file contents",
		},
	}

	copied := deepCopyPart(original)

	original.ToolResponse.Name = "MUTATED"

	if copied.ToolResponse.Name != "read_file" {
		t.Errorf("deepCopyPart() ToolResponse.Name affected by mutation: got %q, want %q",
			copied.ToolResponse.Name, "read_file")
	}
}

func TestDeepCopyPart_Resource(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind:     ai.PartMedia,
		Resource: &ai.ResourcePart{Uri: "https://example.com/image.png"},
	}

	copied := deepCopyPart(original)

	original.Resource.Uri = "MUTATED"

	if copied.Resource.Uri != "https://example.com/image.png" {
		t.Errorf("deepCopyPart() Resource.Uri affected by mutation: got %q, want %q",
			copied.Resource.Uri, "https://example.com/image.png")
	}
}

func TestDeepCopyPart_PartMetadata(t *testing.T) {
	t.Parallel()

	original := &ai.Part{
		Kind:     ai.PartText,
		Text:     "test",
		Custom:   map[string]any{"c": "custom"},
		Metadata: map[string]any{"m": "meta"},
	}

	copied := deepCopyPart(original)

	original.Custom["c"] = "MUTATED"
	original.Metadata["m"] = "MUTATED"

	if copied.Custom["c"] != "custom" {
		t.Errorf("deepCopyPart() Custom map affected: got %q, want %q", copied.Custom["c"], "custom")
	}
	if copied.Metadata["m"] != "meta" {
		t.Errorf("deepCopyPart() Metadata map affected: got %q, want %q", copied.Metadata["m"], "meta")
	}
}

func TestShallowCopyMap_NilInput(t *testing.T) {
	t.Parallel()
	got := shallowCopyMap(nil)
	if got != nil {
		t.Errorf("shallowCopyMap(nil) = %v, want nil", got)
	}
}

func TestShallowCopyMap_IndependentKeys(t *testing.T) {
	t.Parallel()

	original := map[string]any{"a": "1", "b": "2"}
	copied := shallowCopyMap(original)

	// Add new key to original
	original["c"] = "3"

	if _, ok := copied["c"]; ok {
		t.Error("shallowCopyMap() new key in original appeared in copy")
	}
	if len(copied) != 2 {
		t.Errorf("shallowCopyMap() copy len = %d, want 2", len(copied))
	}
}

func TestShallowCopyMap_MutateValue(t *testing.T) {
	t.Parallel()

	original := map[string]any{"key": "value"}
	copied := shallowCopyMap(original)

	// Overwrite original value
	original["key"] = "MUTATED"

	if copied["key"] != "value" {
		t.Errorf("shallowCopyMap() value affected by mutation: got %q, want %q",
			copied["key"], "value")
	}
}
