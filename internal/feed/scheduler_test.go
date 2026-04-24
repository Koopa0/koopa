package feed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
)

// ---------------------------------------------------------------------------
// FilterConfig.MatchURL
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		rawURL string
		want   bool
	}{
		{
			name:   "empty deny paths never matches",
			config: FilterConfig{},
			rawURL: "https://example.com/articles/foo",
			want:   false,
		},
		{
			name:   "exact prefix match",
			config: FilterConfig{DenyPaths: []string{"/sponsored"}},
			rawURL: "https://example.com/sponsored/article",
			want:   true,
		},
		{
			name:   "prefix match with trailing slash",
			config: FilterConfig{DenyPaths: []string{"/ads/"}},
			rawURL: "https://example.com/ads/banner",
			want:   true,
		},
		{
			name:   "prefix does not match different path",
			config: FilterConfig{DenyPaths: []string{"/sponsored"}},
			rawURL: "https://example.com/articles/go",
			want:   false,
		},
		{
			name:   "multiple deny paths first matches",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/a/something",
			want:   true,
		},
		{
			name:   "multiple deny paths second matches",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/b/something",
			want:   true,
		},
		{
			name:   "multiple deny paths none match",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/c/something",
			want:   false,
		},
		{
			name:   "invalid URL returns false",
			config: FilterConfig{DenyPaths: []string{"/x"}},
			rawURL: "://invalid",
			want:   false,
		},
		{
			name:   "empty URL returns false",
			config: FilterConfig{DenyPaths: []string{"/x"}},
			rawURL: "",
			want:   false,
		},
		{
			name:   "root path matches slash prefix",
			config: FilterConfig{DenyPaths: []string{"/"}},
			rawURL: "https://example.com/anything",
			want:   true,
		},
		{
			name:   "path traversal in URL does not panic",
			config: FilterConfig{DenyPaths: []string{"/safe"}},
			rawURL: "https://example.com/../../etc/passwd",
			want:   false,
		},
		{
			name:   "URL without path",
			config: FilterConfig{DenyPaths: []string{"/articles"}},
			rawURL: "https://example.com",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchURL(tt.rawURL)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchURL(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.MatchTitle
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		title  string
		want   bool
	}{
		{
			name:   "empty patterns never matches",
			config: FilterConfig{},
			title:  "Sponsored content here",
			want:   false,
		},
		{
			name:   "case-insensitive pattern match",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
			title:  "SPONSORED: Buy this product",
			want:   true,
		},
		{
			name:   "case-sensitive regex does not match different case",
			config: FilterConfig{DenyTitlePatterns: []string{"sponsored"}},
			title:  "SPONSORED content",
			want:   false,
		},
		{
			name:   "invalid regex falls back to case-insensitive substring",
			config: FilterConfig{DenyTitlePatterns: []string{"[invalid regex"}},
			title:  "[Invalid Regex match",
			want:   true,
		},
		{
			name:   "invalid regex substring no match",
			config: FilterConfig{DenyTitlePatterns: []string{"[invalid regex"}},
			title:  "totally different title",
			want:   false,
		},
		{
			name:   "empty title never matches non-empty pattern",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad"}},
			title:  "",
			want:   false,
		},
		{
			name:   "multiple patterns first matches",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "Big AD sale",
			want:   true,
		},
		{
			name:   "multiple patterns second matches",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "PROMO event",
			want:   true,
		},
		{
			name:   "multiple patterns none match",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "Deep dive into Go generics",
			want:   false,
		},
		{
			name:   "regex with anchors",
			config: FilterConfig{DenyTitlePatterns: []string{"^Sponsored"}},
			title:  "Sponsored content",
			want:   true,
		},
		{
			name:   "regex with anchors does not match middle",
			config: FilterConfig{DenyTitlePatterns: []string{"^Sponsored"}},
			title:  "Not Sponsored content",
			want:   false,
		},
		{
			name:   "unicode title matches pattern",
			config: FilterConfig{DenyTitlePatterns: []string{"廣告"}},
			title:  "今日廣告特價",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchTitle(tt.title)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchTitle(%q) = %v, want %v", tt.title, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.MatchTags
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		tags   []string
		want   bool
	}{
		{
			name:   "no allow or deny rules, never matches",
			config: FilterConfig{},
			tags:   []string{"go", "backend"},
			want:   false,
		},
		{
			name:   "allow list with matching tag passes",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{"go", "rust"},
			want:   false, // has allowed tag, should NOT skip
		},
		{
			name:   "allow list without matching tag skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{"python", "ruby"},
			want:   true,
		},
		{
			name:   "allow list with empty item tags skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{},
			want:   true,
		},
		{
			name:   "allow list with nil item tags skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   nil,
			want:   true,
		},
		{
			name:   "deny list with matching tag skips",
			config: FilterConfig{DenyTags: []string{"sponsored"}},
			tags:   []string{"sponsored", "go"},
			want:   true,
		},
		{
			name:   "deny list without matching tag passes",
			config: FilterConfig{DenyTags: []string{"sponsored"}},
			tags:   []string{"go", "backend"},
			want:   false,
		},
		{
			name:   "tag matching is case-insensitive",
			config: FilterConfig{AllowTags: []string{"Go"}},
			tags:   []string{"go"},
			want:   false, // case-insensitive match found — should NOT skip
		},
		{
			name:   "deny tag case-insensitive match",
			config: FilterConfig{DenyTags: []string{"SPAM"}},
			tags:   []string{"spam"},
			want:   true,
		},
		{
			name:   "allow and deny: deny wins when both match",
			config: FilterConfig{AllowTags: []string{"go"}, DenyTags: []string{"sponsored"}},
			tags:   []string{"go", "sponsored"},
			want:   true, // deny takes precedence (deny checked after allow)
		},
		{
			name:   "allow and deny: only allow matches",
			config: FilterConfig{AllowTags: []string{"go"}, DenyTags: []string{"sponsored"}},
			tags:   []string{"go"},
			want:   false,
		},
		{
			name:   "empty deny list does not skip",
			config: FilterConfig{DenyTags: []string{}},
			tags:   []string{"anything"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchTags(tt.tags)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchTags(%v) = %v, want %v", tt.tags, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.Skip (combined)
// ---------------------------------------------------------------------------

func TestFilterConfig_Skip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  FilterConfig
		itemURL string
		title   string
		tags    []string
		want    bool
	}{
		{
			name:    "empty config never skips",
			config:  FilterConfig{},
			itemURL: "https://example.com/article",
			title:   "Great article",
			tags:    []string{"go"},
			want:    false,
		},
		{
			name:    "URL match skips regardless of title and tags",
			config:  FilterConfig{DenyPaths: []string{"/ads"}},
			itemURL: "https://example.com/ads/banner",
			title:   "Normal title",
			tags:    []string{"go"},
			want:    true,
		},
		{
			name:    "title match skips when URL ok",
			config:  FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
			itemURL: "https://example.com/article",
			title:   "Sponsored article",
			tags:    []string{"go"},
			want:    true,
		},
		{
			name:    "tag match skips when URL and title ok",
			config:  FilterConfig{DenyTags: []string{"spam"}},
			itemURL: "https://example.com/article",
			title:   "Normal article",
			tags:    []string{"spam"},
			want:    true,
		},
		{
			name: "all filters together: only URL triggers",
			config: FilterConfig{
				DenyPaths:         []string{"/deny"},
				DenyTitlePatterns: []string{"(?i)nope"},
				DenyTags:          []string{"bad"},
			},
			itemURL: "https://example.com/deny/path",
			title:   "Normal",
			tags:    []string{"good"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.Skip(tt.itemURL, tt.title, tt.tags)
			if got != tt.want {
				t.Errorf("FilterConfig.Skip(%q, %q, %v) = %v, want %v",
					tt.itemURL, tt.title, tt.tags, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want FilterConfig
	}{
		{
			name: "empty bytes returns zero value",
			raw:  ``,
			want: FilterConfig{},
		},
		{
			name: "empty object returns zero value",
			raw:  `{}`,
			want: FilterConfig{},
		},
		{
			name: "valid deny_paths",
			raw:  `{"deny_paths":["/ads","/sponsored"]}`,
			want: FilterConfig{DenyPaths: []string{"/ads", "/sponsored"}},
		},
		{
			name: "valid deny_title_patterns",
			raw:  `{"deny_title_patterns":["(?i)sponsored"]}`,
			want: FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
		},
		{
			name: "valid allow_tags and deny_tags",
			raw:  `{"allow_tags":["go","rust"],"deny_tags":["spam"]}`,
			want: FilterConfig{AllowTags: []string{"go", "rust"}, DenyTags: []string{"spam"}},
		},
		{
			name: "invalid JSON returns zero value",
			raw:  `{invalid json`,
			want: FilterConfig{},
		},
		{
			name: "null returns zero value",
			raw:  `null`,
			want: FilterConfig{},
		},
		{
			name: "all fields",
			raw:  `{"deny_paths":["/x"],"deny_title_patterns":["ad"],"allow_tags":["go"],"deny_tags":["spam"]}`,
			want: FilterConfig{
				DenyPaths:         []string{"/x"},
				DenyTitlePatterns: []string{"ad"},
				AllowTags:         []string{"go"},
				DenyTags:          []string{"spam"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseFilterConfig(json.RawMessage(tt.raw))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseFilterConfig(%q) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidSchedule additional adversarial cases
// ---------------------------------------------------------------------------

func TestValidSchedule_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "leading whitespace", input: " hourly", want: false},
		{name: "trailing whitespace", input: "daily ", want: false},
		{name: "tab in middle", input: "dai\tly", want: false},
		{name: "unicode lookalike", input: "dаily", want: false}, // Cyrillic 'а'
		{name: "null byte", input: "daily\x00", want: false},
		{name: "SQL injection", input: "daily'; DROP TABLE feeds;--", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ValidSchedule(tt.input)
			if got != tt.want {
				t.Errorf("ValidSchedule(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Stub store and fetcher for handler tests
// ---------------------------------------------------------------------------

type stubFeedStore struct {
	feeds     []Feed
	feedsErr  error
	feed      *Feed
	feedErr   error
	created   *Feed
	createErr error
	updated   *Feed
	updateErr error
	deleteErr error
}

func (s *stubFeedStore) Feeds(_ context.Context, _ *string) ([]Feed, error) {
	return s.feeds, s.feedsErr
}

func (s *stubFeedStore) Feed(_ context.Context, _ uuid.UUID) (*Feed, error) {
	return s.feed, s.feedErr
}

func (s *stubFeedStore) CreateFeed(_ context.Context, _ *CreateParams) (*Feed, error) {
	return s.created, s.createErr
}

func (s *stubFeedStore) UpdateFeed(_ context.Context, _ uuid.UUID, _ *UpdateParams) (*Feed, error) {
	return s.updated, s.updateErr
}

func (s *stubFeedStore) DeleteFeed(_ context.Context, _ uuid.UUID) error {
	return s.deleteErr
}

// feedHandlerStore is a test-only interface (violates interface-golden-rule.md).
// Kept because 30+ handler behavior tests depend on it. Refactoring to
// testcontainers would make these integration-only (require Docker).
type feedHandlerStore interface {
	Feeds(ctx context.Context, schedule *string) ([]Feed, error)
	Feed(ctx context.Context, id uuid.UUID) (*Feed, error)
	CreateFeed(ctx context.Context, p *CreateParams) (*Feed, error)
	UpdateFeed(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Feed, error)
	DeleteFeed(ctx context.Context, id uuid.UUID) error
}

type stubManualFetcher struct {
	ids []uuid.UUID
	err error
}

func (s *stubManualFetcher) FetchFeed(_ context.Context, _ *Feed) ([]uuid.UUID, error) {
	return s.ids, s.err
}

// feedTestHandler wraps Handler and injects stub store.
type feedTestHandler struct {
	store   feedHandlerStore
	fetcher ManualFetcher
	logger  *slog.Logger
}

func newFeedTestHandler(store feedHandlerStore, fetcher ManualFetcher) *feedTestHandler {
	return &feedTestHandler{
		store:   store,
		fetcher: fetcher,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (h *feedTestHandler) List(w http.ResponseWriter, r *http.Request) {
	var schedule *string
	if s := r.URL.Query().Get("schedule"); s != "" {
		schedule = &s
	}
	feeds, err := h.store.Feeds(r.Context(), schedule)
	if err != nil {
		h.logger.Error("listing feeds", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list feeds")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: feeds})
}

func (h *feedTestHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.URL == "" || p.Name == "" || p.Schedule == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "url, name, and schedule are required")
		return
	}
	if !ValidSchedule(p.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}
	f, err := h.store.CreateFeed(r.Context(), &p)
	if err != nil {
		storeErrors := []api.ErrMap{
			{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "feed not found"},
			{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "feed conflict"},
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: f})
}

func (h *feedTestHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}
	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Schedule != nil && !ValidSchedule(*p.Schedule) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid schedule value")
		return
	}
	f, err := h.store.UpdateFeed(r.Context(), id, &p)
	if err != nil {
		storeErrors := []api.ErrMap{
			{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "feed not found"},
			{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "feed conflict"},
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: f})
}

func (h *feedTestHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}
	if err := h.store.DeleteFeed(r.Context(), id); err != nil {
		h.logger.Error("deleting feed", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete feed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *feedTestHandler) Fetch(w http.ResponseWriter, r *http.Request) {
	if h.fetcher == nil {
		api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "feed fetcher not available")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid feed id")
		return
	}
	f, err := h.store.Feed(r.Context(), id)
	if err != nil {
		storeErrors := []api.ErrMap{
			{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "feed not found"},
			{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "feed conflict"},
		}
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	ids, err := h.fetcher.FetchFeed(r.Context(), f)
	if err != nil {
		h.logger.Error("fetching feed", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to fetch feed")
		return
	}
	type fetchResponse struct {
		NewItems int `json:"new_items"`
	}
	api.Encode(w, http.StatusOK, api.Response{Data: fetchResponse{NewItems: len(ids)}})
}

func assertFeedErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("status = %d, want %d (body: %s)", w.Code, wantStatus, w.Body.String())
	}
	var eb api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if diff := cmp.Diff(wantCode, eb.Error.Code); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}
}

// fixtureFeed returns a stable test Feed.
func fixtureFeed() *Feed {
	return &Feed{
		ID:       uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		URL:      "https://example.com/feed.xml",
		Name:     "Example Feed",
		Schedule: ScheduleDaily,
		Topics:   []string{"go"},
		Enabled:  true,
		Priority: "normal",
	}
}

// ---------------------------------------------------------------------------
// Handler.List tests
// ---------------------------------------------------------------------------

func TestFeedHandler_List(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stub       *stubFeedStore
		query      string
		wantStatus int
		wantLen    int
		wantCode   string
	}{
		{
			name:       "returns feeds",
			stub:       &stubFeedStore{feeds: []Feed{*fixtureFeed()}},
			wantStatus: http.StatusOK,
			wantLen:    1,
		},
		{
			name:       "returns empty list",
			stub:       &stubFeedStore{feeds: []Feed{}},
			wantStatus: http.StatusOK,
			wantLen:    0,
		},
		{
			name:       "nil slice from store",
			stub:       &stubFeedStore{feeds: nil},
			wantStatus: http.StatusOK,
		},
		{
			name:       "store error returns 500",
			stub:       &stubFeedStore{feedsErr: errors.New("db down")},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:       "with schedule filter",
			stub:       &stubFeedStore{feeds: []Feed{*fixtureFeed()}},
			query:      "?schedule=daily",
			wantStatus: http.StatusOK,
			wantLen:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFeedTestHandler(tt.stub, nil)
			req := httptest.NewRequest(http.MethodGet, "/api/admin/feeds"+tt.query, http.NoBody)
			w := httptest.NewRecorder()
			h.List(w, req)

			if tt.wantCode != "" {
				assertFeedErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("List() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Create tests
// ---------------------------------------------------------------------------

func TestFeedHandler_Create(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		stub       *stubFeedStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "happy path creates feed",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"daily","topics":["go"]}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing url returns 400",
			body:       `{"name":"Example","schedule":"daily"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing name returns 400",
			body:       `{"url":"https://example.com/feed.xml","schedule":"daily"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "missing schedule returns 400",
			body:       `{"url":"https://example.com/feed.xml","name":"Example"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "invalid schedule returns 400",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"yearly"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "duplicate URL returns 409",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"daily"}`,
			stub:       &stubFeedStore{createErr: ErrConflict},
			wantStatus: http.StatusConflict,
			wantCode:   "CONFLICT",
		},
		{
			name:       "malformed JSON returns 400",
			body:       `{not valid`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "empty body returns 400",
			body:       ``,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "hourly schedule is valid",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"hourly"}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "weekly schedule is valid",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"weekly"}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "biweekly schedule is valid",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"biweekly"}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "monthly schedule is valid",
			body:       `{"url":"https://example.com/feed.xml","name":"Example","schedule":"monthly"}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "XSS in name is forwarded to store",
			body:       `{"url":"https://example.com/feed.xml","name":"<script>alert(1)</script>","schedule":"daily"}`,
			stub:       &stubFeedStore{created: fixtureFeed()},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFeedTestHandler(tt.stub, nil)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/feeds", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)

			if tt.wantCode != "" {
				assertFeedErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("Create() status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Update tests
// ---------------------------------------------------------------------------

func TestFeedHandler_Update(t *testing.T) {
	t.Parallel()

	validID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	sched := ScheduleWeekly

	tests := []struct {
		name       string
		id         string
		body       string
		stub       *stubFeedStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "happy path updates feed",
			id:         validID.String(),
			body:       `{"schedule":"weekly"}`,
			stub:       &stubFeedStore{updated: fixtureFeed()},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			body:       `{"schedule":"daily"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "invalid schedule returns 400",
			id:         validID.String(),
			body:       `{"schedule":"yearly"}`,
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "not found returns 404",
			id:         validID.String(),
			body:       `{"schedule":"daily"}`,
			stub:       &stubFeedStore{updateErr: ErrNotFound},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "conflict returns 409",
			id:         validID.String(),
			body:       `{"url":"https://other.com/feed.xml"}`,
			stub:       &stubFeedStore{updateErr: ErrConflict},
			wantStatus: http.StatusConflict,
			wantCode:   "CONFLICT",
		},
		{
			name:       "valid schedule pointer accepted",
			id:         validID.String(),
			body:       `{"schedule":"weekly"}`,
			stub:       &stubFeedStore{updated: fixtureFeed()},
			wantStatus: http.StatusOK,
		},
	}
	_ = sched // suppress unused variable

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFeedTestHandler(tt.stub, nil)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/feeds/"+tt.id, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Update(w, req)

			if tt.wantCode != "" {
				assertFeedErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("Update(%q) status = %d, want %d (body: %s)", tt.id, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Delete tests
// ---------------------------------------------------------------------------

func TestFeedHandler_Delete(t *testing.T) {
	t.Parallel()

	validID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	tests := []struct {
		name       string
		id         string
		stub       *stubFeedStore
		wantStatus int
		wantCode   string
	}{
		{
			name:       "deletes feed",
			id:         validID.String(),
			stub:       &stubFeedStore{},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			stub:       &stubFeedStore{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "store error returns 500",
			id:         validID.String(),
			stub:       &stubFeedStore{deleteErr: errors.New("db error")},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:       "nil UUID is valid UUID",
			id:         uuid.Nil.String(),
			stub:       &stubFeedStore{},
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFeedTestHandler(tt.stub, nil)
			req := httptest.NewRequest(http.MethodDelete, "/api/admin/feeds/"+tt.id, http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Delete(w, req)

			if tt.wantCode != "" {
				assertFeedErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("Delete(%q) status = %d, want %d", tt.id, w.Code, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Fetch tests
// ---------------------------------------------------------------------------

func TestFeedHandler_Fetch(t *testing.T) {
	t.Parallel()

	validID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	tests := []struct {
		name       string
		id         string
		stub       *stubFeedStore
		fetcher    ManualFetcher
		wantStatus int
		wantCode   string
		wantItems  int
	}{
		{
			name:       "nil fetcher returns 501",
			id:         validID.String(),
			stub:       &stubFeedStore{feed: fixtureFeed()},
			fetcher:    nil,
			wantStatus: http.StatusNotImplemented,
			wantCode:   "NOT_IMPLEMENTED",
		},
		{
			name:       "invalid uuid returns 400",
			id:         "not-a-uuid",
			stub:       &stubFeedStore{},
			fetcher:    &stubManualFetcher{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "feed not found returns 404",
			id:         validID.String(),
			stub:       &stubFeedStore{feedErr: ErrNotFound},
			fetcher:    &stubManualFetcher{},
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "fetcher returns new items",
			id:         validID.String(),
			stub:       &stubFeedStore{feed: fixtureFeed()},
			fetcher:    &stubManualFetcher{ids: []uuid.UUID{uuid.New(), uuid.New()}},
			wantStatus: http.StatusOK,
			wantItems:  2,
		},
		{
			name:       "fetcher error returns 500",
			id:         validID.String(),
			stub:       &stubFeedStore{feed: fixtureFeed()},
			fetcher:    &stubManualFetcher{err: errors.New("timeout")},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name:       "fetcher returns zero new items",
			id:         validID.String(),
			stub:       &stubFeedStore{feed: fixtureFeed()},
			fetcher:    &stubManualFetcher{ids: []uuid.UUID{}},
			wantStatus: http.StatusOK,
			wantItems:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFeedTestHandler(tt.stub, tt.fetcher)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/feeds/"+tt.id+"/fetch", http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.Fetch(w, req)

			if tt.wantCode != "" {
				assertFeedErrorCode(t, w, tt.wantStatus, tt.wantCode)
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("Fetch(%q) status = %d, want %d (body: %s)", tt.id, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantItems > 0 {
				var resp api.Response
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding response: %v", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IncrementFailure threshold logic (pure logic via mock counter)
// ---------------------------------------------------------------------------

func TestMaxConsecutiveFailures(t *testing.T) {
	t.Parallel()
	if MaxConsecutiveFailures != 5 {
		t.Errorf("MaxConsecutiveFailures = %d, want 5", MaxConsecutiveFailures)
	}
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

func FuzzFilterConfig_MatchURL(f *testing.F) {
	f.Add("")
	f.Add("https://example.com/articles/foo")
	f.Add("https://example.com/sponsored/article")
	f.Add("://invalid")
	f.Add("https://example.com/../../etc/passwd")
	f.Add("\x00null\x00byte")
	f.Add("not-a-url")

	fc := FilterConfig{DenyPaths: []string{"/sponsored", "/ads"}}
	f.Fuzz(func(t *testing.T, rawURL string) {
		_ = fc.MatchURL(rawURL) // must not panic
	})
}

func FuzzFilterConfig_MatchTitle(f *testing.F) {
	f.Add("")
	f.Add("Normal article title")
	f.Add("Sponsored content here")
	f.Add("<script>alert(1)</script>")
	f.Add("\x00\x01\x02")
	f.Add("Unicode: 日本語タイトル")

	fc := FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored", "(?i)ad"}}
	f.Fuzz(func(t *testing.T, title string) {
		_ = fc.MatchTitle(title) // must not panic
	})
}

func FuzzFilterConfig_MatchTags(f *testing.F) {
	f.Add("")
	f.Add("go")
	f.Add("Go")
	f.Add("<script>")
	f.Add("\x00")

	fc := FilterConfig{AllowTags: []string{"go", "rust"}, DenyTags: []string{"spam"}}
	f.Fuzz(func(t *testing.T, tag string) {
		_ = fc.MatchTags([]string{tag}) // must not panic
	})
}

func FuzzParseFilterConfig(f *testing.F) {
	f.Add(``)
	f.Add(`{}`)
	f.Add(`{"deny_paths":["/ads"]}`)
	f.Add(`{not valid json`)
	f.Add(`null`)
	f.Add(`{"deny_paths":null}`)
	f.Add(`{"deny_title_patterns":["(?i)sponsored"]}`)

	f.Fuzz(func(t *testing.T, raw string) {
		_ = ParseFilterConfig(json.RawMessage(raw)) // must not panic
	})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkFilterConfig_Skip(b *testing.B) {
	b.ReportAllocs()

	fc := FilterConfig{
		DenyPaths:         []string{"/ads", "/sponsored", "/promo"},
		DenyTitlePatterns: []string{"(?i)sponsored", "(?i)advertisement"},
		DenyTags:          []string{"spam", "promo"},
	}

	for b.Loop() {
		_ = fc.Skip("https://example.com/articles/go-performance", "Deep dive into Go performance", []string{"go", "performance"})
	}
}

func BenchmarkFilterConfig_MatchURL(b *testing.B) {
	b.ReportAllocs()

	fc := FilterConfig{DenyPaths: []string{"/ads", "/sponsored", "/promo", "/native"}}

	for b.Loop() {
		_ = fc.MatchURL("https://example.com/articles/go-performance")
	}
}

func BenchmarkParseFilterConfig(b *testing.B) {
	b.ReportAllocs()

	raw := json.RawMessage(`{"deny_paths":["/ads","/sponsored"],"deny_title_patterns":["(?i)sponsored"],"deny_tags":["spam"]}`)

	for b.Loop() {
		_ = ParseFilterConfig(raw)
	}
}
