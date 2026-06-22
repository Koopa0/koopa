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
	"testing/synctest"
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
// vectors are "missing".
type fakeSource struct {
	listErr error

	mu      sync.Mutex
	docs    []Document
	vectors map[uuid.UUID]pgvector.Vector
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
		readings      int
		songs         int
		failSubstring string
		want          Result
	}{
		{
			// 120 contents force three drain iterations (50+50+20).
			name:     "drains the content source across batches",
			contents: 120,
			want:     Result{BySource: map[string]int{"contents": 120, "readings": 0, "songs": 0}},
		},
		{
			name: "empty sources do nothing but report every source",
			want: Result{BySource: map[string]int{"contents": 0, "readings": 0, "songs": 0}},
		},
		{
			// Every wired source is drained in one pass; counts are kept
			// per source.
			name:     "drains content reading and song sources independently",
			contents: 4,
			readings: 3,
			songs:    2,
			want:     Result{BySource: map[string]int{"contents": 4, "readings": 3, "songs": 2}},
		},
		{
			// The failing row is skipped and stays missing; the rest of
			// the batch persists. Only the reading source has the failing
			// title, so the failure is attributed to it and content/song
			// drain fully.
			name:          "failed row skipped others persist across sources",
			contents:      2,
			readings:      3,
			songs:         2,
			failSubstring: "reading-001",
			want:          Result{BySource: map[string]int{"contents": 2, "readings": 2, "songs": 2}, Failed: 1},
		},
		{
			// Every row in one source fails: that drain stops after one
			// zero-success batch while the siblings still drain.
			name:          "one source all-failing terminates without starving siblings",
			contents:      3,
			readings:      5,
			songs:         1,
			failSubstring: "reading-",
			want:          Result{BySource: map[string]int{"contents": 3, "readings": 0, "songs": 1}, Failed: 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := newFakeSource(tt.contents, "content")
			readings := newFakeSource(tt.readings, "reading")
			songs := newFakeSource(tt.songs, "song")
			emb := &stubEmbedder{failSubstring: tt.failSubstring}
			r := NewReconciler(emb, slog.New(slog.DiscardHandler),
				NamedSource{Name: "contents", Source: contents},
				NamedSource{Name: "readings", Source: readings},
				NamedSource{Name: "songs", Source: songs},
			)

			got, err := r.RunOnce(t.Context())
			if err != nil {
				t.Fatalf("RunOnce() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
			}

			for name, src := range map[string]*fakeSource{"contents": contents, "readings": readings, "songs": songs} {
				if n := src.embeddedCount(); n != tt.want.BySource[name] {
					t.Errorf("%s persisted = %d, want %d", name, n, tt.want.BySource[name])
				}
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

func TestReconcilerRunOnce_ListErrorReturned(t *testing.T) {
	// The failing source is drained second, so the error names it specifically
	// and the first source still records its progress.
	good := newFakeSource(2, "content")
	bad := newFakeSource(0, "reading")
	bad.listErr = errors.New("list boom")
	r := NewReconciler(&stubEmbedder{}, slog.New(slog.DiscardHandler),
		NamedSource{Name: "contents", Source: good},
		NamedSource{Name: "readings", Source: bad},
	)

	got, err := r.RunOnce(t.Context())
	if err == nil {
		t.Fatal("RunOnce() error = nil, want readings listing error")
	}
	if !strings.Contains(err.Error(), "draining readings") {
		t.Errorf("RunOnce() error = %q, want it to mention draining readings", err)
	}
	want := Result{BySource: map[string]int{"contents": 2, "readings": 0}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
	}
}

func TestReconcilerRunOnce_CanceledContext(t *testing.T) {
	contents := newFakeSource(5, "content")
	emb := &stubEmbedder{}
	r := NewReconciler(emb, slog.New(slog.DiscardHandler),
		NamedSource{Name: "contents", Source: contents})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := r.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce() error = %v, want context.Canceled", err)
	}
	want := Result{BySource: map[string]int{"contents": 0}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RunOnce() result mismatch (-want +got):\n%s", diff)
	}
	if emb.calls != 0 {
		t.Errorf("embed calls = %d, want 0 on canceled context", emb.calls)
	}
}

func TestReconcilerRun_StopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		contents := newFakeSource(2, "content")
		r := NewReconciler(&stubEmbedder{}, slog.New(slog.DiscardHandler),
			NamedSource{Name: "contents", Source: contents})

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			r.Run(ctx, time.Hour)
			close(done)
		}()

		// Run is blocked on the ticker once Wait returns, and the test
		// never advances the fake clock, so no tick has fired: whatever
		// is persisted at this point came from the initial pass alone.
		synctest.Wait()
		if n := contents.embeddedCount(); n != 2 {
			t.Errorf("initial pass: contents persisted = %d, want 2", n)
		}

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("Run did not return after ctx cancel")
		}
	})
}

func TestNewReconciler_PanicsOnMisconfiguration(t *testing.T) {
	emb := &stubEmbedder{}
	logger := slog.New(slog.DiscardHandler)
	good := newFakeSource(0, "content")

	tests := []struct {
		name    string
		build   func()
		wantMsg string
	}{
		{
			name:    "no sources",
			build:   func() { NewReconciler(emb, logger) },
			wantMsg: "at least one source",
		},
		{
			name:    "nil source",
			build:   func() { NewReconciler(emb, logger, NamedSource{Name: "contents", Source: nil}) },
			wantMsg: "non-nil Source",
		},
		{
			name:    "empty name",
			build:   func() { NewReconciler(emb, logger, NamedSource{Name: "", Source: good}) },
			wantMsg: "non-empty Name",
		},
		{
			name: "duplicate name",
			build: func() {
				NewReconciler(emb, logger,
					NamedSource{Name: "dup", Source: good},
					NamedSource{Name: "dup", Source: good},
				)
			},
			wantMsg: "duplicate dup",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("NewReconciler(%s) did not panic", tt.name)
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, tt.wantMsg) {
					t.Errorf("panic = %v, want message containing %q", r, tt.wantMsg)
				}
			}()
			tt.build()
		})
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
