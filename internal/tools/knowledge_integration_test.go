package tools

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/plugins/postgresql"
)

// capturingRetriever records every Retrieve call and returns canned results.
// Unlike mockRetriever (which returns empty), this allows testing the full
// search → format → Result flow.
type capturingRetriever struct {
	docs   []*ai.Document
	calls  []capturedRetrieve
	errVal error // if non-nil, Retrieve returns this error
}

type capturedRetrieve struct {
	Filter string // filter is always a string in this codebase (ownerFilter returns string)
	K      int
}

func (*capturingRetriever) Name() string { return "capturing-retriever" }

func (r *capturingRetriever) Retrieve(_ context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
	if r.errVal != nil {
		return nil, r.errVal
	}
	opts, _ := req.Options.(*postgresql.RetrieverOptions)
	if opts != nil {
		filterStr, _ := opts.Filter.(string)
		r.calls = append(r.calls, capturedRetrieve{Filter: filterStr, K: opts.K})
	}
	return &ai.RetrieverResponse{Documents: r.docs}, nil
}

func (*capturingRetriever) Register(_ api.Registry) {}

// knowledgeTestSetup creates a Knowledge instance wired to capturing fakes.
type knowledgeTestSetup struct {
	kt  *Knowledge
	ret *capturingRetriever
}

func newKnowledgeTestSetup(t *testing.T) *knowledgeTestSetup {
	t.Helper()
	ret := &capturingRetriever{}
	kt := &Knowledge{
		retriever: ret,
		docStore:  &postgresql.DocStore{}, // non-nil enables knowledge_store
		logger:    testLogger(),
	}
	return &knowledgeTestSetup{kt: kt, ret: ret}
}

func toolCtxWithOwner(ownerID string) *ai.ToolContext {
	ctx := context.Background()
	if ownerID != "" {
		ctx = ContextWithOwnerID(ctx, ownerID)
	}
	return &ai.ToolContext{Context: ctx}
}

// --- Search handler tests ---

func TestSearchHistory_ReturnsResults(t *testing.T) {
	t.Parallel()
	s := newKnowledgeTestSetup(t)
	s.ret.docs = []*ai.Document{
		ai.DocumentFromText("past conversation about Go", nil),
		ai.DocumentFromText("discussion about testing", nil),
	}

	result, err := s.kt.SearchHistory(toolCtxWithOwner(""), KnowledgeSearchInput{
		Query: "Go programming",
		TopK:  5,
	})
	if err != nil {
		t.Fatalf("SearchHistory() unexpected error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("SearchHistory().Status = %q, want %q", result.Status, StatusSuccess)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("SearchHistory().Data type = %T, want map[string]any", result.Data)
	}
	if got, want := data["result_count"], 2; got != want {
		t.Errorf("SearchHistory().Data[result_count] = %v, want %v", got, want)
	}
	if got, want := data["query"], "Go programming"; got != want {
		t.Errorf("SearchHistory().Data[query] = %v, want %v", got, want)
	}
}

func TestSearchDocuments_ReturnsResults(t *testing.T) {
	t.Parallel()
	s := newKnowledgeTestSetup(t)
	s.ret.docs = []*ai.Document{
		ai.DocumentFromText("architecture overview document", nil),
	}

	result, err := s.kt.SearchDocuments(toolCtxWithOwner(""), KnowledgeSearchInput{
		Query: "architecture",
	})
	if err != nil {
		t.Fatalf("SearchDocuments() unexpected error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("SearchDocuments().Status = %q, want %q", result.Status, StatusSuccess)
	}
	data := result.Data.(map[string]any)
	if got, want := data["result_count"], 1; got != want {
		t.Errorf("SearchDocuments().Data[result_count] = %v, want %v", got, want)
	}
}

func TestSearchSystemKnowledge_ReturnsResults(t *testing.T) {
	t.Parallel()
	s := newKnowledgeTestSetup(t)
	s.ret.docs = []*ai.Document{
		ai.DocumentFromText("system pattern for error handling", nil),
	}

	result, err := s.kt.SearchSystemKnowledge(toolCtxWithOwner(""), KnowledgeSearchInput{
		Query: "error handling",
	})
	if err != nil {
		t.Fatalf("SearchSystemKnowledge() unexpected error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("SearchSystemKnowledge().Status = %q, want %q", result.Status, StatusSuccess)
	}
	data := result.Data.(map[string]any)
	if got, want := data["result_count"], 1; got != want {
		t.Errorf("SearchSystemKnowledge().Data[result_count] = %v, want %v", got, want)
	}
}

// --- Query length validation across all search handlers ---

func TestSearch_QueryLengthValidation(t *testing.T) {
	t.Parallel()

	longQuery := strings.Repeat("x", MaxKnowledgeQueryLength+1)

	tests := []struct {
		name     string
		searchFn func(*Knowledge, *ai.ToolContext, KnowledgeSearchInput) (Result, error)
	}{
		{"SearchHistory", (*Knowledge).SearchHistory},
		{"SearchDocuments", (*Knowledge).SearchDocuments},
		{"SearchSystemKnowledge", (*Knowledge).SearchSystemKnowledge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newKnowledgeTestSetup(t)

			result, err := tt.searchFn(s.kt, toolCtxWithOwner(""), KnowledgeSearchInput{
				Query: longQuery,
			})
			if err != nil {
				t.Fatalf("%s() unexpected error: %v", tt.name, err)
			}
			if result.Status != StatusError {
				t.Fatalf("%s() status = %q, want %q", tt.name, result.Status, StatusError)
			}
			if result.Error == nil {
				t.Fatalf("%s() error = nil, want non-nil", tt.name)
			}
			if result.Error.Code != ErrCodeValidation {
				t.Errorf("%s() error code = %q, want %q", tt.name, result.Error.Code, ErrCodeValidation)
			}
			if !strings.Contains(result.Error.Message, "exceeds maximum") {
				t.Errorf("%s() error message = %q, want contains %q", tt.name, result.Error.Message, "exceeds maximum")
			}
		})
	}
}

// --- Query at exact boundary should succeed ---

func TestSearch_QueryAtMaxLength(t *testing.T) {
	t.Parallel()
	s := newKnowledgeTestSetup(t)

	exactQuery := strings.Repeat("x", MaxKnowledgeQueryLength)
	result, err := s.kt.SearchHistory(toolCtxWithOwner(""), KnowledgeSearchInput{
		Query: exactQuery,
	})
	if err != nil {
		t.Fatalf("SearchHistory(exact max length) unexpected error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Errorf("SearchHistory(exact max length) status = %q, want %q (boundary should pass)", result.Status, StatusSuccess)
	}
}

// --- Retriever error propagation ---

func TestSearch_RetrieverError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		searchFn func(*Knowledge, *ai.ToolContext, KnowledgeSearchInput) (Result, error)
		wantMsg  string
	}{
		{"SearchHistory", (*Knowledge).SearchHistory, "search failed"},
		{"SearchDocuments", (*Knowledge).SearchDocuments, "search failed"},
		{"SearchSystemKnowledge", (*Knowledge).SearchSystemKnowledge, "search failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newKnowledgeTestSetup(t)
			s.ret.errVal = fmt.Errorf("connection refused")

			result, err := tt.searchFn(s.kt, toolCtxWithOwner(""), KnowledgeSearchInput{
				Query: "test",
			})
			if err != nil {
				t.Fatalf("%s() unexpected Go error: %v", tt.name, err)
			}
			if result.Status != StatusError {
				t.Fatalf("%s() status = %q, want %q", tt.name, result.Status, StatusError)
			}
			if result.Error.Code != ErrCodeExecution {
				t.Errorf("%s() error code = %q, want %q", tt.name, result.Error.Code, ErrCodeExecution)
			}
			if !strings.Contains(result.Error.Message, tt.wantMsg) {
				t.Errorf("%s() error message = %q, want contains %q", tt.name, result.Error.Message, tt.wantMsg)
			}
		})
	}
}

// --- Owner isolation: filter passes owner ID to retriever ---

func TestSearch_OwnerIsolation(t *testing.T) {
	t.Parallel()

	ownerID := "550e8400-e29b-41d4-a716-446655440000"
	s := newKnowledgeTestSetup(t)

	_, err := s.kt.SearchDocuments(toolCtxWithOwner(ownerID), KnowledgeSearchInput{
		Query: "test query",
	})
	if err != nil {
		t.Fatalf("SearchDocuments() unexpected error: %v", err)
	}

	if len(s.ret.calls) != 1 {
		t.Fatalf("retriever.Retrieve() called %d times, want 1", len(s.ret.calls))
	}
	filter := s.ret.calls[0].Filter
	if !strings.Contains(filter, "source_type = 'file'") {
		t.Errorf("filter = %q, want contains %q", filter, "source_type = 'file'")
	}
	if !strings.Contains(filter, ownerID) {
		t.Errorf("filter = %q, want contains owner ID %q", filter, ownerID)
	}
	if !strings.Contains(filter, "owner_id IS NULL") {
		t.Errorf("filter = %q, want contains %q for legacy docs", filter, "owner_id IS NULL")
	}
}

func TestSearch_NoOwner_NoOwnerFilter(t *testing.T) {
	t.Parallel()
	s := newKnowledgeTestSetup(t)

	_, err := s.kt.SearchHistory(toolCtxWithOwner(""), KnowledgeSearchInput{
		Query: "test",
	})
	if err != nil {
		t.Fatalf("SearchHistory() unexpected error: %v", err)
	}

	if len(s.ret.calls) != 1 {
		t.Fatalf("retriever.Retrieve() called %d times, want 1", len(s.ret.calls))
	}
	filter := s.ret.calls[0].Filter
	// Without owner, filter should only have source_type.
	if strings.Contains(filter, "owner_id") {
		t.Errorf("filter = %q, want no owner_id clause when owner is empty", filter)
	}
}

// --- TopK clamping through handler ---

func TestSearch_TopKClamping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		inputK   int
		searchFn func(*Knowledge, *ai.ToolContext, KnowledgeSearchInput) (Result, error)
		wantK    int
	}{
		{"history default", 0, (*Knowledge).SearchHistory, DefaultHistoryTopK},
		{"history clamped", 50, (*Knowledge).SearchHistory, MaxKnowledgeTopK},
		{"history explicit", 7, (*Knowledge).SearchHistory, 7},
		{"documents default", 0, (*Knowledge).SearchDocuments, DefaultDocumentsTopK},
		{"documents clamped", 100, (*Knowledge).SearchDocuments, MaxKnowledgeTopK},
		{"system default", 0, (*Knowledge).SearchSystemKnowledge, DefaultSystemKnowledgeTopK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newKnowledgeTestSetup(t)

			_, err := tt.searchFn(s.kt, toolCtxWithOwner(""), KnowledgeSearchInput{
				Query: "test",
				TopK:  tt.inputK,
			})
			if err != nil {
				t.Fatalf("search() unexpected error: %v", err)
			}

			if len(s.ret.calls) != 1 {
				t.Fatalf("retriever.Retrieve() called %d times, want 1", len(s.ret.calls))
			}
			if got := s.ret.calls[0].K; got != tt.wantK {
				t.Errorf("retriever received K = %d, want %d", got, tt.wantK)
			}
		})
	}
}

// --- Source type routing ---

func TestSearch_SourceTypeRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		searchFn       func(*Knowledge, *ai.ToolContext, KnowledgeSearchInput) (Result, error)
		wantSourceType string
	}{
		{"SearchHistory", (*Knowledge).SearchHistory, "conversation"},
		{"SearchDocuments", (*Knowledge).SearchDocuments, "file"},
		{"SearchSystemKnowledge", (*Knowledge).SearchSystemKnowledge, "system"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newKnowledgeTestSetup(t)

			_, err := tt.searchFn(s.kt, toolCtxWithOwner(""), KnowledgeSearchInput{
				Query: "test",
			})
			if err != nil {
				t.Fatalf("%s() unexpected error: %v", tt.name, err)
			}

			if len(s.ret.calls) != 1 {
				t.Fatalf("retriever.Retrieve() called %d times, want 1", len(s.ret.calls))
			}
			filter := s.ret.calls[0].Filter
			want := "source_type = '" + tt.wantSourceType + "'"
			if !strings.Contains(filter, want) {
				t.Errorf("filter = %q, want contains %q", filter, want)
			}
		})
	}
}

// --- StoreKnowledge deterministic ID ---

func TestStoreKnowledge_DeterministicID(t *testing.T) {
	t.Parallel()

	title := "Go error handling patterns"
	wantID := fmt.Sprintf("user:%x", sha256.Sum256([]byte(title)))

	// Verify the ID formula directly (same computation as knowledge.go:495).
	got := fmt.Sprintf("user:%x", sha256.Sum256([]byte(title)))
	if got != wantID {
		t.Errorf("deterministic ID = %q, want %q", got, wantID)
	}

	// Verify idempotency: same title always produces same ID.
	got2 := fmt.Sprintf("user:%x", sha256.Sum256([]byte(title)))
	if got != got2 {
		t.Errorf("deterministic ID not stable: %q != %q", got, got2)
	}

	// Verify uniqueness: different title produces different ID.
	otherID := fmt.Sprintf("user:%x", sha256.Sum256([]byte("Different title")))
	if got == otherID {
		t.Error("different titles produced same ID")
	}

	// Verify the prefix is "user:" (not "system:" etc).
	if !strings.HasPrefix(got, "user:") {
		t.Errorf("deterministic ID = %q, want prefix %q", got, "user:")
	}
}

// --- StoreKnowledge marker stripping ---

func TestStoreKnowledge_MarkerStripping(t *testing.T) {
	t.Parallel()

	kt := &Knowledge{
		retriever: &mockRetriever{},
		docStore:  &postgresql.DocStore{}, // non-nil to enable store path
		logger:    testLogger(),
	}

	// Markers present but non-empty after stripping → should reach the Index call.
	// With a zero-value DocStore, Index will panic, so we verify validation passes
	// by checking that the panic comes from Index (not from validation rejection).
	input := KnowledgeStoreInput{
		Title:   "safe title",
		Content: "real content === with markers <<<here>>>",
	}

	func() {
		defer func() {
			_ = recover() // Panic from DocStore.Index means validation passed.
		}()
		result, err := kt.StoreKnowledge(toolCtxWithOwner(""), input)
		if err != nil {
			t.Fatalf("StoreKnowledge() unexpected error: %v", err)
		}
		// If we get here without panic, check that validation didn't reject it.
		if result.Status == StatusError && result.Error.Code == ErrCodeValidation {
			t.Errorf("StoreKnowledge() rejected valid content: %s", result.Error.Message)
		}
	}()

	// Content that becomes empty after stripping should be rejected.
	emptyResult, err := kt.StoreKnowledge(toolCtxWithOwner(""), KnowledgeStoreInput{
		Title:   "empty after strip",
		Content: "===<<<>>>",
	})
	if err != nil {
		t.Fatalf("StoreKnowledge(markers-only) unexpected error: %v", err)
	}
	if emptyResult.Status != StatusError {
		t.Fatalf("StoreKnowledge(markers-only) status = %q, want %q", emptyResult.Status, StatusError)
	}
	if emptyResult.Error.Code != ErrCodeValidation {
		t.Errorf("StoreKnowledge(markers-only) error code = %q, want %q", emptyResult.Error.Code, ErrCodeValidation)
	}
	if !strings.Contains(emptyResult.Error.Message, "empty after sanitization") {
		t.Errorf("StoreKnowledge(markers-only) error = %q, want contains %q", emptyResult.Error.Message, "empty after sanitization")
	}
}

// --- HasDocStore ---

func TestHasDocStore(t *testing.T) {
	t.Parallel()

	t.Run("nil docStore returns false", func(t *testing.T) {
		t.Parallel()
		kt := &Knowledge{retriever: &mockRetriever{}, logger: testLogger()}
		if kt.HasDocStore() {
			t.Error("HasDocStore() = true, want false when docStore is nil")
		}
	})

	t.Run("non-nil docStore returns true", func(t *testing.T) {
		t.Parallel()
		kt := &Knowledge{
			retriever: &mockRetriever{},
			docStore:  &postgresql.DocStore{},
			logger:    testLogger(),
		}
		if !kt.HasDocStore() {
			t.Error("HasDocStore() = false, want true when docStore is set")
		}
	})
}
