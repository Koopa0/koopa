package content

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestParseFilter_Since verifies that parseFilter extracts the since query param.
func TestParseFilter_Since(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		query     string
		wantSince *time.Time
	}{
		{name: "missing", query: "", wantSince: nil},
		{name: "valid date", query: "since=2026-03-20", wantSince: timePtr(2026, 3, 20)},
		{name: "invalid format", query: "since=march-20", wantSince: nil},
		{name: "empty value", query: "since=", wantSince: nil},
	}

	h := &Handler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := h.parsePublicFilter(httptest.NewRequest(http.MethodGet, "/?"+tt.query, http.NoBody))
			assertTimePtr(t, "Since", tt.query, f.Since, tt.wantSince)
		})
	}
}

// TestParseFilter_Type verifies that parseFilter extracts the type query param.
func TestParseFilter_Type(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantType *Type
	}{
		{name: "missing", query: "", wantType: nil},
		{name: "valid type", query: "type=til", wantType: new(TypeTIL)},
		{name: "invalid type ignored", query: "type=podcast", wantType: nil},
	}

	h := &Handler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := h.parsePublicFilter(httptest.NewRequest(http.MethodGet, "/?"+tt.query, http.NoBody))
			assertTypePtr(t, tt.query, f.Type, tt.wantType)
		})
	}
}

func assertTimePtr(t *testing.T, field, query string, got, want *time.Time) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("parseFilter(%q).%s = %v, want nil", query, field, *got)
	case want != nil && got == nil:
		t.Errorf("parseFilter(%q).%s = nil, want %v", query, field, *want)
	case want != nil && got != nil && !got.Equal(*want):
		t.Errorf("parseFilter(%q).%s = %v, want %v", query, field, *got, *want)
	}
}

func assertTypePtr(t *testing.T, query string, got, want *Type) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("parseFilter(%q).Type = %v, want nil", query, *got)
	case want != nil && got == nil:
		t.Errorf("parseFilter(%q).Type = nil, want %v", query, *want)
	case want != nil && got != nil && *got != *want:
		t.Errorf("parseFilter(%q).Type = %v, want %v", query, *got, *want)
	}
}

func timePtr(year, month, day int) *time.Time {
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return &t
}
