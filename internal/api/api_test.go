package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestParsePagination verifies query param parsing for pagination.
// Scene: API clients send per_page=50&page=3 — incorrect parsing breaks list endpoints.
func TestParsePagination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		query       string
		wantPage    int
		wantPerPage int
	}{
		{name: "defaults when no params", query: "", wantPage: 1, wantPerPage: 20},
		{name: "explicit page and per_page", query: "page=3&per_page=50", wantPage: 3, wantPerPage: 50},
		{name: "per_page clamped to 100", query: "per_page=200", wantPage: 1, wantPerPage: 100},
		{name: "negative page clamped to 1", query: "page=-1", wantPage: 1, wantPerPage: 20},
		{name: "zero page clamped to 1", query: "page=0", wantPage: 1, wantPerPage: 20},
		{name: "non-numeric page uses default", query: "page=abc", wantPage: 1, wantPerPage: 20},
		{name: "zero per_page clamped to 1", query: "per_page=0", wantPage: 1, wantPerPage: 1},
		{name: "negative per_page clamped to 1", query: "per_page=-5", wantPage: 1, wantPerPage: 1},
		{name: "per_page exactly 100 allowed", query: "per_page=100", wantPage: 1, wantPerPage: 100},
		{name: "per_page 101 clamped to 100", query: "per_page=101", wantPage: 1, wantPerPage: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("GET", "/items?"+tt.query, http.NoBody)
			page, perPage := ParsePagination(r)
			if page != tt.wantPage {
				t.Errorf("ParsePagination(%q) page = %d, want %d", tt.query, page, tt.wantPage)
			}
			if perPage != tt.wantPerPage {
				t.Errorf("ParsePagination(%q) perPage = %d, want %d", tt.query, perPage, tt.wantPerPage)
			}
		})
	}
}

// TestPagedResponse verifies pagination metadata computation.
// Scene: frontend needs total_pages to render pagination controls —
// off-by-one here breaks the last page.
func TestPagedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		total          int
		page           int
		perPage        int
		wantTotalPages int
	}{
		{name: "exact division", total: 100, page: 1, perPage: 20, wantTotalPages: 5},
		{name: "remainder adds page", total: 101, page: 1, perPage: 20, wantTotalPages: 6},
		{name: "single item", total: 1, page: 1, perPage: 20, wantTotalPages: 1},
		{name: "zero items", total: 0, page: 1, perPage: 20, wantTotalPages: 0},
		{name: "items equal per_page", total: 20, page: 1, perPage: 20, wantTotalPages: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := PagedResponse(nil, tt.total, tt.page, tt.perPage)
			if resp.Meta == nil {
				t.Fatal("PagedResponse meta is nil")
			}
			if resp.Meta.TotalPages != tt.wantTotalPages {
				t.Errorf("PagedResponse(%d, %d, %d).TotalPages = %d, want %d",
					tt.total, tt.page, tt.perPage, resp.Meta.TotalPages, tt.wantTotalPages)
			}
		})
	}
}

// TestEncode verifies JSON encoding sets correct headers and status.
// Scene: all API responses go through Encode — wrong content-type breaks frontend parsing.
func TestEncode(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	Encode(w, http.StatusCreated, data)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var got map[string]string
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if diff := cmp.Diff(data, got); diff != "" {
		t.Errorf("response body mismatch (-want +got):\n%s", diff)
	}
}

// TestError verifies the standard error response format.
// Scene: frontend relies on error.code to display localized messages —
// wrong structure breaks error handling.
func TestError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	Error(w, http.StatusNotFound, "not_found", "content not found")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var got ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	want := ErrorBody{Error: ErrorDetail{Code: "not_found", Message: "content not found"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Error response mismatch (-want +got):\n%s", diff)
	}
}

// TestDecode verifies JSON request body decoding with size limit.
// Scene: API receives POST body — oversized body must be rejected.
func TestDecode(t *testing.T) {
	t.Parallel()

	t.Run("valid body", func(t *testing.T) {
		t.Parallel()
		body := `{"name":"test"}`
		r := httptest.NewRequest("POST", "/items", strings.NewReader(body))
		w := httptest.NewRecorder()

		type item struct {
			Name string `json:"name"`
		}
		got, err := Decode[item](w, r)
		if err != nil {
			t.Fatalf("Decode() error: %v", err)
		}
		if got.Name != "test" {
			t.Errorf("Decode().Name = %q, want %q", got.Name, "test")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest("POST", "/items", strings.NewReader("not json"))
		w := httptest.NewRecorder()

		type item struct{ Name string }
		_, err := Decode[item](w, r)
		if err == nil {
			t.Error("Decode(invalid json) = nil error, want error")
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		t.Parallel()
		// 2 MB body should exceed the 1 MB limit
		bigBody := strings.NewReader(strings.Repeat("x", 2<<20))
		r := httptest.NewRequest("POST", "/items", bigBody)
		w := httptest.NewRecorder()

		type item struct{ Name string }
		_, err := Decode[item](w, r)
		if err == nil {
			t.Error("Decode(oversized body) = nil error, want error")
		}
	})
}

// ---------------------------------------------------------------------------
// ParsePagination — adversarial + security
// ---------------------------------------------------------------------------

func TestParsePagination_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		query       string
		wantPage    int
		wantPerPage int
	}{
		// SQL injection attempts (URL-encoded to avoid breaking httptest)
		{name: "SQL injection in page", query: "page=1%3BDROP%20TABLE", wantPage: 1, wantPerPage: 20},
		{name: "SQL injection in per_page", query: "per_page=20%3BDROP%20TABLE", wantPage: 1, wantPerPage: 20},

		// overflow / large values
		{name: "max int page", query: "page=2147483647", wantPage: 2147483647, wantPerPage: 20},
		{name: "very large per_page", query: "per_page=999999", wantPage: 1, wantPerPage: 100},

		// special characters
		{name: "null bytes in page", query: "page=1%00", wantPage: 1, wantPerPage: 20},
		{name: "float page", query: "page=1.5", wantPage: 1, wantPerPage: 20},
		{name: "float per_page", query: "per_page=20.5", wantPage: 1, wantPerPage: 20},
		{name: "unicode digits", query: "page=١٢٣", wantPage: 1, wantPerPage: 20},
		{name: "empty values", query: "page=&per_page=", wantPage: 1, wantPerPage: 20},

		// boundary
		{name: "per_page exactly 1", query: "per_page=1", wantPage: 1, wantPerPage: 1},
		{name: "page exactly 1", query: "page=1", wantPage: 1, wantPerPage: 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("GET", "/items?"+tt.query, http.NoBody)
			page, perPage := ParsePagination(r)
			if page != tt.wantPage {
				t.Errorf("ParsePagination(%q) page = %d, want %d", tt.query, page, tt.wantPage)
			}
			if perPage != tt.wantPerPage {
				t.Errorf("ParsePagination(%q) perPage = %d, want %d", tt.query, perPage, tt.wantPerPage)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HandleError — sentinel error mapping
// ---------------------------------------------------------------------------

func TestHandleError(t *testing.T) {
	t.Parallel()

	sentinel := http.ErrNoCookie // just any error for testing

	tests := []struct {
		name        string
		err         error
		maps        []ErrMap
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{
			name:        "matched sentinel",
			err:         sentinel,
			maps:        []ErrMap{{Target: sentinel, Status: 404, Code: "NOT_FOUND", Message: "item not found"}},
			wantStatus:  404,
			wantCode:    "NOT_FOUND",
			wantMessage: "item not found",
		},
		{
			name:        "unmatched error returns 500",
			err:         http.ErrAbortHandler,
			maps:        []ErrMap{{Target: sentinel, Status: 404, Code: "NOT_FOUND", Message: "item not found"}},
			wantStatus:  500,
			wantCode:    "INTERNAL",
			wantMessage: "internal server error",
		},
		{
			name: "first match wins",
			err:  sentinel,
			maps: []ErrMap{
				{Target: sentinel, Status: 404, Code: "FIRST", Message: "first match"},
				{Target: sentinel, Status: 409, Code: "SECOND", Message: "second match"},
			},
			wantStatus:  404,
			wantCode:    "FIRST",
			wantMessage: "first match",
		},
		{
			name:        "no mappings returns 500",
			err:         sentinel,
			maps:        nil,
			wantStatus:  500,
			wantCode:    "INTERNAL",
			wantMessage: "internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			logger := slog.New(slog.DiscardHandler)
			HandleError(w, logger, tt.err, tt.maps...)

			if w.Code != tt.wantStatus {
				t.Errorf("HandleError() status = %d, want %d", w.Code, tt.wantStatus)
			}
			var body ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decoding error response: %v", err)
			}
			if body.Error.Code != tt.wantCode {
				t.Errorf("HandleError() code = %q, want %q", body.Error.Code, tt.wantCode)
			}
			if body.Error.Message != tt.wantMessage {
				t.Errorf("HandleError() message = %q, want %q", body.Error.Message, tt.wantMessage)
			}
		})
	}
}

// TestHandleError_PanicsOnMissingMessage asserts the strict-Message
// contract: an ErrMap declared without a client-facing Message is a
// programmer bug, and HandleError panics at request time rather than
// leaking the sentinel's internal Error() text to the client. Recovery
// middleware catches the panic in production and returns a 500.
func TestHandleError_PanicsOnMissingMessage(t *testing.T) {
	t.Parallel()

	sentinel := http.ErrNoCookie
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("HandleError did not panic on empty Message")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value = %T, want string", r)
		}
		if !strings.Contains(msg, "Message is required") {
			t.Errorf("panic message = %q, want to contain %q", msg, "Message is required")
		}
	}()

	w := httptest.NewRecorder()
	logger := slog.New(slog.DiscardHandler)
	HandleError(w, logger, sentinel, ErrMap{Target: sentinel, Status: 404, Code: "NOT_FOUND"})
}

// ---------------------------------------------------------------------------
// Encode — does not leak internal errors in 5xx
// ---------------------------------------------------------------------------

func TestEncode_NilData(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	Encode(w, http.StatusOK, Response{Data: nil})

	var got Response
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.Data != nil {
		t.Errorf("Encode(nil data).Data = %v, want nil", got.Data)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkEncode(b *testing.B) {
	data := Response{Data: map[string]string{"id": "abc", "title": "test"}}
	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		Encode(w, http.StatusOK, data)
	}
}

func BenchmarkParsePagination(b *testing.B) {
	r := httptest.NewRequest("GET", "/items?page=3&per_page=50", http.NoBody)
	b.ReportAllocs()
	for b.Loop() {
		ParsePagination(r)
	}
}

func FuzzParsePagination(f *testing.F) {
	f.Add("page=1&per_page=20")
	f.Add("")
	f.Add("page=-1&per_page=999")
	f.Add("page=abc&per_page=xyz")
	f.Add("page=0&per_page=0")
	f.Add("page=2147483647&per_page=2147483647")

	f.Fuzz(func(t *testing.T, query string) {
		r := httptest.NewRequest("GET", "/items?"+query, http.NoBody)
		page, perPage := ParsePagination(r)
		if page < 1 {
			t.Errorf("ParsePagination(%q) page = %d, want >= 1", query, page)
		}
		if perPage < 1 || perPage > 100 {
			t.Errorf("ParsePagination(%q) perPage = %d, want [1,100]", query, perPage)
		}
	})
}
