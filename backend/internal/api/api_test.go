package api

import (
	"encoding/json"
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
		{name: "per_page capped at 100", query: "per_page=200", wantPage: 1, wantPerPage: 20},
		{name: "negative page uses default", query: "page=-1", wantPage: 1, wantPerPage: 20},
		{name: "zero page uses default", query: "page=0", wantPage: 1, wantPerPage: 20},
		{name: "non-numeric page uses default", query: "page=abc", wantPage: 1, wantPerPage: 20},
		{name: "zero per_page uses default", query: "per_page=0", wantPage: 1, wantPerPage: 20},
		{name: "per_page exactly 100 allowed", query: "per_page=100", wantPage: 1, wantPerPage: 100},
		{name: "per_page 101 rejected", query: "per_page=101", wantPage: 1, wantPerPage: 20},
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

// BenchmarkEncode measures JSON encoding overhead per response.
// Scene: every API response goes through Encode — this is the hot path.
func BenchmarkEncode(b *testing.B) {
	data := Response{Data: map[string]string{"id": "abc", "title": "test"}}
	for b.Loop() {
		w := httptest.NewRecorder()
		Encode(w, http.StatusOK, data)
	}
}
