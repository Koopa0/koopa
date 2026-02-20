package testutil

import (
	"context"
	"math"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestMockLLM_PatternMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []struct{ pattern, response string }
		input    string
		want     string
	}{
		{
			name:  "fallback when no patterns",
			input: "hello",
			want:  "default response",
		},
		{
			name: "exact match",
			patterns: []struct{ pattern, response string }{
				{"hello", "hi there"},
			},
			input: "hello",
			want:  "hi there",
		},
		{
			name: "case insensitive match",
			patterns: []struct{ pattern, response string }{
				{"hello", "hi there"},
			},
			input: "HELLO world",
			want:  "hi there",
		},
		{
			name: "first match wins",
			patterns: []struct{ pattern, response string }{
				{"hello", "first"},
				{"hello", "second"},
			},
			input: "hello",
			want:  "first",
		},
		{
			name: "no match returns fallback",
			patterns: []struct{ pattern, response string }{
				{"hello", "hi"},
			},
			input: "goodbye",
			want:  "default response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewMockLLM("default response")
			for _, p := range tt.patterns {
				m.AddResponse(p.pattern, p.response)
			}

			req := &ai.ModelRequest{
				Messages: []*ai.Message{
					ai.NewUserMessage(ai.NewTextPart(tt.input)),
				},
			}

			resp, err := m.generate(context.Background(), req, nil)
			if err != nil {
				t.Fatalf("generate() unexpected error: %v", err)
			}
			if got := resp.Message.Text(); got != tt.want {
				t.Errorf("generate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMockLLM_CallRecording(t *testing.T) {
	t.Parallel()
	m := NewMockLLM("ok")
	m.AddResponse("special", "special response")

	// Make two calls
	req1 := &ai.ModelRequest{
		Messages: []*ai.Message{ai.NewUserMessage(ai.NewTextPart("hello"))},
	}
	req2 := &ai.ModelRequest{
		Messages: []*ai.Message{ai.NewUserMessage(ai.NewTextPart("special input"))},
	}

	if _, err := m.generate(context.Background(), req1, nil); err != nil {
		t.Fatalf("generate() unexpected error: %v", err)
	}
	if _, err := m.generate(context.Background(), req2, nil); err != nil {
		t.Fatalf("generate() unexpected error: %v", err)
	}

	want := []MockCall{
		{UserMessage: "hello", Response: "ok"},
		{UserMessage: "special input", Response: "special response"},
	}
	if diff := cmp.Diff(want, m.Calls()); diff != "" {
		t.Errorf("Calls() mismatch (-want +got):\n%s", diff)
	}

	// Test Reset
	m.Reset()
	if got := len(m.Calls()); got != 0 {
		t.Errorf("Calls() after Reset() len = %d, want 0", got)
	}
}

func TestMockLLM_Streaming(t *testing.T) {
	t.Parallel()
	m := NewMockLLM("streamed")

	var chunks []string
	cb := func(_ context.Context, chunk *ai.ModelResponseChunk) error {
		for _, p := range chunk.Content {
			chunks = append(chunks, p.Text)
		}
		return nil
	}

	req := &ai.ModelRequest{
		Messages: []*ai.Message{ai.NewUserMessage(ai.NewTextPart("test"))},
	}

	if _, err := m.generate(context.Background(), req, cb); err != nil {
		t.Fatalf("generate() unexpected error: %v", err)
	}

	if diff := cmp.Diff([]string{"streamed"}, chunks); diff != "" {
		t.Errorf("streaming chunks mismatch (-want +got):\n%s", diff)
	}
}

func TestMockLLM_RegisterModel(t *testing.T) {
	t.Parallel()
	m := NewMockLLM("registered")
	g := genkit.Init(context.Background())

	model := m.RegisterModel(g)
	if model == nil {
		t.Fatal("RegisterModel() returned nil")
	}
	if got := model.Name(); got != "mock/test-model" {
		t.Errorf("RegisterModel().Name() = %q, want %q", got, "mock/test-model")
	}

	// Verify model can be looked up
	found := genkit.LookupModel(g, "mock/test-model")
	if found == nil {
		t.Fatal("LookupModel() returned nil after registration")
	}
}

func TestMockEmbedder_DeterministicVector(t *testing.T) {
	t.Parallel()
	e := NewMockEmbedder(768)

	// Same content should produce same vector
	v1 := e.vectorFor("test content")
	v2 := e.vectorFor("test content")

	if diff := cmp.Diff(v1, v2); diff != "" {
		t.Errorf("vectorFor() same content produced different vectors:\n%s", diff)
	}

	// Different content should produce different vectors
	v3 := e.vectorFor("different content")
	if cmp.Equal(v1, v3) {
		t.Error("vectorFor() different content produced same vector")
	}

	// Vector should be normalized (unit length)
	var norm float64
	for _, val := range v1 {
		norm += float64(val) * float64(val)
	}
	norm = math.Sqrt(norm)
	if diff := math.Abs(norm - 1.0); diff > 0.01 {
		t.Errorf("vectorFor() norm = %f, want ~1.0", norm)
	}
}

func TestMockEmbedder_ExplicitVector(t *testing.T) {
	t.Parallel()
	e := NewMockEmbedder(3)

	custom := []float32{0.1, 0.2, 0.3}
	e.SetVector("special", custom)

	got := e.vectorFor("special")
	if diff := cmp.Diff(custom, got, cmpopts.EquateApprox(0, 0.001)); diff != "" {
		t.Errorf("vectorFor(\"special\") mismatch (-want +got):\n%s", diff)
	}

	// Non-mapped content should still use hash
	other := e.vectorFor("other")
	if cmp.Equal(custom, other) {
		t.Error("vectorFor(\"other\") should not match explicit vector")
	}
}

func TestMockEmbedder_RegisterEmbedder(t *testing.T) {
	t.Parallel()
	e := NewMockEmbedder(768)
	g := genkit.Init(context.Background())

	embedder := e.RegisterEmbedder(g)
	if embedder == nil {
		t.Fatal("RegisterEmbedder() returned nil")
	}
	if got := embedder.Name(); got != "mock/test-embedder" {
		t.Errorf("RegisterEmbedder().Name() = %q, want %q", got, "mock/test-embedder")
	}
}

func TestMockEmbedder_Embed(t *testing.T) {
	t.Parallel()
	e := NewMockEmbedder(768)

	req := &ai.EmbedRequest{
		Input: []*ai.Document{
			ai.DocumentFromText("hello world", nil),
			ai.DocumentFromText("goodbye world", nil),
		},
	}

	resp, err := e.embed(context.Background(), req)
	if err != nil {
		t.Fatalf("embed() unexpected error: %v", err)
	}

	if got, want := len(resp.Embeddings), 2; got != want {
		t.Fatalf("embed() returned %d embeddings, want %d", got, want)
	}

	// Each embedding should have correct dimensions
	for i, emb := range resp.Embeddings {
		if got, want := len(emb.Embedding), 768; got != want {
			t.Errorf("embed() embedding[%d] dim = %d, want %d", i, got, want)
		}
	}

	// Different documents should have different embeddings
	if cmp.Equal(resp.Embeddings[0].Embedding, resp.Embeddings[1].Embedding) {
		t.Error("embed() different documents produced same embedding")
	}
}
