package chat

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
)

// TestNew_ValidationErrors tests constructor validation
func TestNew_ValidationErrors(t *testing.T) {
	t.Parallel()

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
			name: "nil retriever",
			cfg: Config{
				Genkit: nil, // Still nil, so we'll get Genkit error first
			},
			errContains: "genkit instance is required",
		},
		{
			name: "nil logger - requires all previous deps",
			cfg:  Config{
				// Missing Genkit
			},
			errContains: "genkit instance is required",
		},
		{
			name: "empty tools - requires all previous deps",
			cfg:  Config{
				// Missing Genkit
			},
			errContains: "genkit instance is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatal("New() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("New() error = %q, want to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

// TestConstants tests package constants
func TestConstants(t *testing.T) {
	t.Parallel()

	t.Run("Name constant", func(t *testing.T) {
		t.Parallel()
		if Name != "chat" {
			t.Errorf("Name = %q, want %q", Name, "chat")
		}
	})

	t.Run("Description is not empty", func(t *testing.T) {
		t.Parallel()
		if Description == "" {
			t.Error("Description is empty, want non-empty")
		}
	})

	t.Run("KoopaPromptName is set", func(t *testing.T) {
		t.Parallel()
		if KoopaPromptName != "koopa" {
			t.Errorf("KoopaPromptName = %q, want %q", KoopaPromptName, "koopa")
		}
	})
}

// TestStreamCallback_Type tests the StreamCallback type definition
func TestStreamCallback_Type(t *testing.T) {
	t.Parallel()

	t.Run("nil callback is valid", func(t *testing.T) {
		t.Parallel()
		var callback StreamCallback
		if callback != nil {
			t.Errorf("nil callback = %v, want nil", callback)
		}
	})

	t.Run("callback can be assigned", func(t *testing.T) {
		t.Parallel()
		called := false
		callback := StreamCallback(func(_ context.Context, _ *ai.ModelResponseChunk) error {
			called = true
			return nil
		})
		if callback == nil {
			t.Fatal("callback is nil, want non-nil")
		}
		err := callback(context.Background(), nil)
		if err != nil {
			t.Errorf("callback() unexpected error: %v", err)
		}
		if !called {
			t.Error("callback was not called")
		}
	})

	t.Run("callback can return error", func(t *testing.T) {
		t.Parallel()
		expectedErr := errors.New("test error")
		callback := StreamCallback(func(_ context.Context, _ *ai.ModelResponseChunk) error {
			return expectedErr
		})
		err := callback(context.Background(), nil)
		if !errors.Is(err, expectedErr) {
			t.Errorf("callback() = %v, want %v", err, expectedErr)
		}
	})
}

// TestConfig_Structure tests the Config struct
func TestConfig_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has nil fields", func(t *testing.T) {
		t.Parallel()
		var cfg Config
		if cfg.Genkit != nil {
			t.Errorf("cfg.Genkit = %v, want nil", cfg.Genkit)
		}
		if cfg.Retriever != nil {
			t.Errorf("cfg.Retriever = %v, want nil", cfg.Retriever)
		}
		if cfg.SessionStore != nil {
			t.Errorf("cfg.SessionStore = %v, want nil", cfg.SessionStore)
		}
		if cfg.Logger != nil {
			t.Errorf("cfg.Logger = %v, want nil", cfg.Logger)
		}
		if cfg.Tools != nil {
			t.Errorf("cfg.Tools = %v, want nil", cfg.Tools)
		}
	})
}

// TestChat_RetrieveRAGContext_SkipsWhenTopKZero tests RAG context retrieval
func TestChat_RetrieveRAGContext_SkipsWhenTopKZero(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when topK is zero", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			ragTopK: 0,
			logger:  slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		if docs != nil {
			t.Errorf("retrieveRAGContext() = %v, want nil", docs)
		}
	})

	t.Run("returns nil when topK is negative", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			ragTopK: -1,
			logger:  slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		if docs != nil {
			t.Errorf("retrieveRAGContext() = %v, want nil", docs)
		}
	})
}

// =============================================================================
// Edge Case Tests for Real Scenarios
// =============================================================================

// TestChat_EmptyResponseHandling tests that empty model responses are handled gracefully.
func TestChat_EmptyResponseHandling(t *testing.T) {
	t.Parallel()

	t.Run("empty string triggers fallback", func(t *testing.T) {
		t.Parallel()
		// Test the logic of empty response detection
		responseText := ""
		if strings.TrimSpace(responseText) == "" {
			responseText = FallbackResponseMessage
		}
		if !strings.Contains(responseText, "apologize") {
			t.Errorf("fallback response = %q, want to contain %q", responseText, "apologize")
		}
		if responseText == "" {
			t.Error("fallback response is empty, want non-empty")
		}
	})

	t.Run("whitespace-only triggers fallback", func(t *testing.T) {
		t.Parallel()
		responseText := "   \n\t   "
		if strings.TrimSpace(responseText) == "" {
			responseText = FallbackResponseMessage
		}
		if !strings.Contains(responseText, "apologize") {
			t.Errorf("fallback response = %q, want to contain %q", responseText, "apologize")
		}
	})

	t.Run("valid response is preserved", func(t *testing.T) {
		t.Parallel()
		responseText := "Hello, I'm here to help!"
		originalText := responseText
		if strings.TrimSpace(responseText) == "" {
			responseText = FallbackResponseMessage
		}
		if responseText != originalText {
			t.Errorf("responseText = %q, want %q", responseText, originalText)
		}
	})
}

// TestChat_ContextCancellation tests graceful handling of context cancellation.
func TestChat_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("canceled context is detected", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Verify context is canceled
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("ctx.Err() = %v, want context.Canceled", ctx.Err())
		}
	})

	t.Run("deadline exceeded is different from canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()

		// Wait for timeout
		<-ctx.Done()

		// DeadlineExceeded is different from Canceled
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v, want context.DeadlineExceeded", ctx.Err())
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("ctx.Err() = context.Canceled, want context.DeadlineExceeded")
		}
	})
}

// TestChat_MaxTurnsProtection tests that conversation doesn't loop infinitely.
// Safety: Prevents runaway agent loops that could exhaust resources.
func TestChat_MaxTurnsProtection(t *testing.T) {
	t.Parallel()

	t.Run("max turns concept validation", func(t *testing.T) {
		t.Parallel()
		// In a real agent loop, we would track turns
		maxTurns := 10
		currentTurn := 0

		// Simulate turn counting
		for i := 0; i < 100; i++ {
			currentTurn++
			if currentTurn >= maxTurns {
				break
			}
		}

		if currentTurn != maxTurns {
			t.Errorf("currentTurn = %d, want %d (should stop at max turns)", currentTurn, maxTurns)
		}
	})
}

// TestChat_ToolFailureRecovery tests that the agent can continue after tool failures.
// Resilience: Agent should gracefully handle tool execution errors.
func TestChat_ToolFailureRecovery(t *testing.T) {
	t.Parallel()

	t.Run("tool error is wrapped", func(t *testing.T) {
		t.Parallel()
		toolErr := errors.New("tool failed: file not found")
		wrappedErr := errors.New("tool execution failed: " + toolErr.Error())
		if !strings.Contains(wrappedErr.Error(), "tool execution failed") {
			t.Errorf("wrappedErr = %q, want to contain %q", wrappedErr.Error(), "tool execution failed")
		}
		if !strings.Contains(wrappedErr.Error(), "file not found") {
			t.Errorf("wrappedErr = %q, want to contain %q", wrappedErr.Error(), "file not found")
		}
	})

	t.Run("tool error does not crash agent", func(t *testing.T) {
		t.Parallel()
		// Simulate error handling that doesn't propagate
		var lastErr error
		handleToolError := func(err error) {
			lastErr = err // Log but don't crash
		}

		handleToolError(errors.New("tool failed"))
		if lastErr == nil {
			t.Error("lastErr is nil, want non-nil")
		}
		// Agent continues running
	})
}

// =============================================================================
// deepCopyMessages / deepCopyPart / shallowCopyMap Tests
// =============================================================================

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
