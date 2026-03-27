package learning

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseIntParam(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		query      string
		paramName  string
		min, max   int
		defaultVal int
		want       int
	}{
		{name: "missing uses default", query: "", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 90},
		{name: "valid value", query: "days=30", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 30},
		{name: "above max clamped", query: "days=999", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 365},
		{name: "below min uses default", query: "days=-5", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 90},
		{name: "zero uses default", query: "days=0", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 90},
		{name: "non-numeric uses default", query: "days=abc", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 90},
		{name: "boundary min", query: "days=1", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 1},
		{name: "boundary max", query: "days=365", paramName: "days", min: 1, max: 365, defaultVal: 90, want: 365},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url := "/test"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, url, http.NoBody)
			got := parseIntParam(req, tt.paramName, tt.min, tt.max, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseIntParam(%q, %q, %d, %d, %d) = %d, want %d",
					tt.query, tt.paramName, tt.min, tt.max, tt.defaultVal, got, tt.want)
			}
		})
	}
}
