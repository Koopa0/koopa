package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegression_ParsePaginationClamp verifies that out-of-range per_page
// values are CLAMPED to the valid range, not silently defaulted.
//
// Regression: the original implementation returned the default value (20) for
// per_page=0 and per_page=-5. The correct behavior is to clamp to 1, because:
//   - Returning 20 when per_page=0 was provided silently ignores the caller's
//     intent. A caller asking for 0 items should get the minimum (1), not a
//     different non-zero value.
//   - page=0 similarly should clamp to 1, not fall through to default 1 by
//     coincidence. The semantics are "clamp", not "default on invalid".
//
// If the fix were reverted (clamp removed, default returned instead),
// per_page=0 would return 20 and this test would fail.
func TestRegression_ParsePaginationClamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		query       string
		wantPage    int
		wantPerPage int
	}{
		// These are the specific regression cases: values that were previously
		// defaulted to 20 instead of clamped to 1.
		{
			name:        "per_page=0 clamps to 1 not default 20",
			query:       "per_page=0",
			wantPage:    1,
			wantPerPage: 1, // before fix: returned 20 (the default)
		},
		{
			name:        "per_page=-5 clamps to 1 not default 20",
			query:       "per_page=-5",
			wantPage:    1,
			wantPerPage: 1, // before fix: returned 20 (the default)
		},
		{
			name:        "per_page=-1 clamps to 1 not default 20",
			query:       "per_page=-1",
			wantPage:    1,
			wantPerPage: 1, // before fix: returned 20 (the default)
		},
		// page=0 clamps to 1. The value is 1 both before and after fix,
		// but the semantic is now "clamp" not "return default by coincidence".
		// We assert both page AND per_page to ensure page=0 does not affect per_page.
		{
			name:        "page=0 clamps to 1 and does not affect per_page",
			query:       "page=0&per_page=50",
			wantPage:    1,
			wantPerPage: 50,
		},
		{
			name:        "page=-1 clamps to 1 and does not affect per_page",
			query:       "page=-1&per_page=50",
			wantPage:    1,
			wantPerPage: 50,
		},
		// Confirm that per_page is clamped at the top boundary too.
		{
			name:        "per_page=101 clamps to 100 not 20",
			query:       "per_page=101",
			wantPage:    1,
			wantPerPage: 100,
		},
		{
			name:        "per_page=99999 clamps to 100",
			query:       "per_page=99999",
			wantPage:    1,
			wantPerPage: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("GET", "/items?"+tt.query, http.NoBody)
			page, perPage := ParsePagination(r)
			if page != tt.wantPage {
				t.Errorf("ParsePagination(%q) page = %d, want %d (should clamp, not default)",
					tt.query, page, tt.wantPage)
			}
			if perPage != tt.wantPerPage {
				t.Errorf("ParsePagination(%q) perPage = %d, want %d (should clamp, not default)",
					tt.query, perPage, tt.wantPerPage)
			}
		})
	}
}
