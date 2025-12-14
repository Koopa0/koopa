package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHTMX_WithHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("HX-Request", "true")

	assert.True(t, IsHTMX(req), "should return true when HX-Request header is 'true'")
}

func TestIsHTMX_WithoutHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	// No HX-Request header

	assert.False(t, IsHTMX(req), "should return false when HX-Request header is missing")
}

func TestIsHTMX_WrongValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  string
		expect bool
	}{
		{"empty string", "", false},
		{"false", "false", false},
		{"TRUE (uppercase)", "TRUE", false}, // HTMX always sends lowercase "true"
		{"True (mixed)", "True", false},
		{"1", "1", false},
		{"yes", "yes", false},
		{"true (correct)", "true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("HX-Request", tt.value)

			assert.Equal(t, tt.expect, IsHTMX(req))
		})
	}
}

func TestIsHTMX_POST(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("POST", "/api/data", nil)
	req.Header.Set("HX-Request", "true")

	assert.True(t, IsHTMX(req), "should work with POST requests")
}

func TestIsHTMX_DELETE(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("DELETE", "/api/resource/123", nil)
	req.Header.Set("HX-Request", "true")

	assert.True(t, IsHTMX(req), "should work with DELETE requests")
}

// TestIsHTMX_HeaderConstant verifies the constant matches HTMX spec.
func TestIsHTMX_HeaderConstant(t *testing.T) {
	t.Parallel()

	// HTMX sends "HX-Request" header (case-insensitive in HTTP, but this is canonical)
	assert.Equal(t, "HX-Request", htmxRequestHeader)
	assert.Equal(t, "true", htmxRequestTrue)
}
