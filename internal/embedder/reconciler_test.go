// Copyright 2026 Koopa. All rights reserved.

package embedder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"
)

// stubEmbedder returns deterministic vectors without network access:
// element 0 carries the input length, the rest stay zero. Inputs whose
// text contains failSubstring error instead.
type stubEmbedder struct {
	failSubstring string

	mu    sync.Mutex
	calls int
}

func (e *stubEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	if e.failSubstring != "" && strings.Contains(text, e.failSubstring) {
		return nil, errors.New("stub embed failure")
	}
	vec := make([]float32, Dimension)
	vec[0] = float32(len(text))
	return vec, nil
}

// fakeSource is an in-memory Source: docs whose ID has no entry in
// vectors are "missing". drained (optional) is closed once every doc has
// a persisted vector.
type fakeSource struct {
	listErr error
	drained chan struct{}

	mu          sync.Mutex
	docs        []Document
	vectors     map[uuid.UUID]pgvector.Vector
	drainedOnce sync.Once
}

func newFakeSource(n int, titlePrefix string) *fakeSource {
	src := &fakeSource{
		docs:    make([]Document, 0, n),
		vectors: make(map[uuid.UUID]pgvector.Vector),
	}
	for i := range n {
		src.docs = append(src.docs, Document{
			ID:    uuid.New(),
			Title: fmt.Sprintf("%s-%03d", titlePrefix, i),
			Body:  "body of " + titlePrefix,
		})
	}
	return src
}

func (f *fakeSource) MissingEmbeddings(_ context.Context, limit int) ([]Document, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Document, 0, limit)
	for _, d := range f.docs {
		if _, ok := f.vectors[d.ID]; ok {
			continue
		}
		out = append(out, d)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeSource) SetEmbedding(_ context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vectors[id] = embedding
	if len(f.vectors) == len(f.docs) && f.drained != nil {
		f.drainedOnce.Do(func() { close(f.drained) })
	}
	return nil
}

func (f *fakeSource) embeddedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.vectors)
}

func TestReconcilerRunOnce(t *testing.T) {
	tests := []struct {
		name          string
		contents      int
		notes         int
		failSubstring string
		want          Result
	}{
		{
			// 120 contents force three drain iterations (50+50+20).
			name:     "drains both sources across batches",
			contents: 120,
			notes:    30,
			want:     Result{Contents: 120, Notes: 30},
		},
		{
			name: "empty sources do nothing",
			want: Result{},
		},
		{
			// The failing row is skipped and stays missing; the rest of
			// the batch persists.
			name:          "failed row skipped others persist",
			contents:      3,
			notes:         2,
			failSubstring: "content-001",
			want:          Result{Contents: 2, Notes: 2, Failed: 1},
		},
		{
			// Every row fails: each source stops after one zero-success
			// batch instead of refetching the same rows forever.
			name:          "all rows failing terminates",
			contents:      50,
			notes:         10,
			failSubstring: "-",
			want:          Result{Failed: 60},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := newFakeSource(tt.contents, "content")
			notes := newFakeSource(tt.notes, "note")
			emb := &stubEmbedder{failSubstring: tt.failSubstring}
			r := NewReconciler(emb, contents, notes, slog.New(slog.DiscardHandler))

			got, err := r.RunOnce(t.Context())
			if err != nil {
				t.Fatalf("RunOnce() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
			}

			if n := contents.embeddedCount(); n != tt.want.Contents {
				t.Errorf("contents persisted = %d, want %d", n, tt.want.Contents)
			}
			if n := notes.embeddedCount(); n != tt.want.Notes {
				t.Errorf("notes persisted = %d, want %d", n, tt.want.Notes)
			}
			for _, src := range []*fakeSource{contents, notes} {
				for _, d := range src.docs {
					vec, ok := src.vectors[d.ID]
					shouldFail := tt.failSubstring != "" && strings.Contains(d.Title, tt.failSubstring)
					if shouldFail && ok {
						t.Errorf("doc %q has an embedding, want none (embed fails for it)", d.Title)
					}
					if !shouldFail && !ok {
						t.Errorf("doc %q has no embedding, want one", d.Title)
					}
					if ok && len(vec.Slice()) != Dimension {
						t.Errorf("doc %q embedding dims = %d, want %d", d.Title, len(vec.Slice()), Dimension)
					}
				}
			}
		})
	}
}

func TestReconcilerRunOnce_ListErrorStillDrainsOtherSource(t *testing.T) {
	contents := newFakeSource(0, "content")
	contents.listErr = errors.New("list boom")
	notes := newFakeSource(2, "note")
	r := NewReconciler(&stubEmbedder{}, contents, notes, slog.New(slog.DiscardHandler))

	got, err := r.RunOnce(t.Context())
	if err == nil {
		t.Fatal("RunOnce() error = nil, want contents listing error")
	}
	if !strings.Contains(err.Error(), "draining contents") {
		t.Errorf("RunOnce() error = %q, want it to mention draining contents", err)
	}
	want := Result{Notes: 2}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
	}
}

func TestReconcilerRunOnce_CanceledContext(t *testing.T) {
	contents := newFakeSource(5, "content")
	notes := newFakeSource(5, "note")
	emb := &stubEmbedder{}
	r := NewReconciler(emb, contents, notes, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := r.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce() error = %v, want context.Canceled", err)
	}
	if diff := cmp.Diff(Result{}, got); diff != "" {
		t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
	}
	if emb.calls != 0 {
		t.Errorf("embed calls = %d, want 0 on canceled context", emb.calls)
	}
}

func TestReconcilerRun_StopsOnCancel(t *testing.T) {
	contents := newFakeSource(2, "content")
	notes := newFakeSource(1, "note")
	notes.drained = make(chan struct{})
	r := NewReconciler(&stubEmbedder{}, contents, notes, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, time.Hour)
		close(done)
	}()

	// The initial pass runs before any tick: notes (drained second)
	// reporting empty means both sources are done.
	select {
	case <-notes.drained:
	case <-time.After(5 * time.Second):
		t.Fatal("initial pass did not drain within 5s")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of ctx cancel")
	}

	if n := contents.embeddedCount(); n != 2 {
		t.Errorf("contents persisted = %d, want 2", n)
	}
	if n := notes.embeddedCount(); n != 1 {
		t.Errorf("notes persisted = %d, want 1", n)
	}
}

func TestEmbedText(t *testing.T) {
	tests := []struct {
		name  string
		title string
		body  string
		want  string
	}{
		{name: "title and body joined", title: "T", body: "B", want: "T\n\nB"},
		{name: "empty body embeds title alone", title: "T", body: "", want: "T"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := embedText(tt.title, tt.body); got != tt.want {
				t.Errorf("embedText(%q, %q) = %q, want %q", tt.title, tt.body, got, tt.want)
			}
		})
	}
}

func TestEmbedText_CapsOversizedBody(t *testing.T) {
	// 3-byte CJK runes guarantee the byte cap lands mid-rune somewhere.
	body := strings.Repeat("界", maxEmbedBodyBytes/3+100)
	got := embedText("title", body)

	if !utf8.ValidString(got) {
		t.Error("embedText() produced invalid UTF-8")
	}
	if !strings.HasPrefix(got, "title\n\n") {
		t.Errorf("embedText() = %q..., want title prefix", got[:20])
	}
	if capBytes := len("title\n\n") + maxEmbedBodyBytes; len(got) > capBytes {
		t.Errorf("embedText() length = %d, want <= %d", len(got), capBytes)
	}
}

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{name: "shorter than cap unchanged", s: "abc", n: 10, want: "abc"},
		{name: "exact cap unchanged", s: "abc", n: 3, want: "abc"},
		{name: "ascii cut at cap", s: "abcdef", n: 4, want: "abcd"},
		{name: "cut mid-rune backs off", s: "a界", n: 2, want: "a"},
		{name: "cut mid-rune backs off to empty", s: "界", n: 2, want: ""},
		{name: "cut at rune boundary kept", s: "a界b", n: 4, want: "a界"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateUTF8(tt.s, tt.n); got != tt.want {
				t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}
