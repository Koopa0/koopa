package embedder

import (
	"errors"
	"testing"
)

func TestNew_EmptyAPIKey(t *testing.T) {
	t.Parallel()
	_, err := New(t.Context(), "")
	if err == nil {
		t.Fatal("New(empty apiKey) error = nil, want non-nil")
	}
}

func TestEmbed_EmptyInput(t *testing.T) {
	t.Parallel()
	// Construct an Embedder with a placeholder key. Embed short-circuits on
	// empty input before touching the network, so the key value is irrelevant.
	e, err := New(t.Context(), "test-key-does-not-hit-network")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	_, err = e.Embed(t.Context(), "")
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("Embed(\"\") error = %v, want %v", err, ErrEmptyInput)
	}
}

func TestModelAndDimension(t *testing.T) {
	t.Parallel()
	// Guard-rail: the two constants travel with persisted embeddings. A
	// change here must be paired with a schema migration + re-embed. The
	// test exists to make the intent explicit at commit time — anyone
	// flipping these values has to update the test in the same diff.
	if Model != "gemini-embedding-2-preview" {
		t.Errorf("Model = %q, want %q", Model, "gemini-embedding-2-preview")
	}
	if Dimension != 1536 {
		t.Errorf("Dimension = %d, want 1536", Dimension)
	}
}
