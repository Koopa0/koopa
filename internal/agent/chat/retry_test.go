package chat

import (
	"errors"
	"testing"
)

func TestDefaultRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()

	if cfg.MaxRetries <= 0 {
		t.Errorf("MaxRetries should be positive, got %d", cfg.MaxRetries)
	}
	if cfg.InitialInterval <= 0 {
		t.Errorf("InitialInterval should be positive, got %v", cfg.InitialInterval)
	}
	if cfg.MaxInterval <= 0 {
		t.Errorf("MaxInterval should be positive, got %v", cfg.MaxInterval)
	}
	if cfg.MaxInterval < cfg.InitialInterval {
		t.Error("MaxInterval should be >= InitialInterval")
	}
}

func TestRetryableError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "rate limit error",
			err:      errors.New("rate limit exceeded"),
			expected: true,
		},
		{
			name:     "quota exceeded error",
			err:      errors.New("quota exceeded for project"),
			expected: true,
		},
		{
			name:     "429 status code",
			err:      errors.New("HTTP 429: Too Many Requests"),
			expected: true,
		},
		{
			name:     "500 server error",
			err:      errors.New("HTTP 500 Internal Server Error"),
			expected: true,
		},
		{
			name:     "502 bad gateway",
			err:      errors.New("502 Bad Gateway"),
			expected: true,
		},
		{
			name:     "503 unavailable",
			err:      errors.New("503 Service Unavailable"),
			expected: true,
		},
		{
			name:     "504 gateway timeout",
			err:      errors.New("504 Gateway Timeout"),
			expected: true,
		},
		{
			name:     "unavailable keyword",
			err:      errors.New("service unavailable"),
			expected: true,
		},
		{
			name:     "connection reset",
			err:      errors.New("connection reset by peer"),
			expected: true,
		},
		{
			name:     "timeout error",
			err:      errors.New("request timeout"),
			expected: true,
		},
		{
			name:     "temporary error",
			err:      errors.New("temporary failure"),
			expected: true,
		},
		{
			name:     "non-retryable error",
			err:      errors.New("invalid API key"),
			expected: false,
		},
		{
			name:     "non-retryable 400 error",
			err:      errors.New("HTTP 400 Bad Request"),
			expected: false,
		},
		{
			name:     "non-retryable 401 error",
			err:      errors.New("HTTP 401 Unauthorized"),
			expected: false,
		},
		{
			name:     "non-retryable 403 error",
			err:      errors.New("HTTP 403 Forbidden"),
			expected: false,
		},
		{
			name:     "case insensitive rate limit",
			err:      errors.New("RATE LIMIT reached"),
			expected: true,
		},
		{
			name:     "case insensitive timeout",
			err:      errors.New("TIMEOUT occurred"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := retryableError(tt.err)
			if got != tt.expected {
				t.Errorf("retryableError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		s        string
		substrs  []string
		expected bool
	}{
		{
			name:     "empty string",
			s:        "",
			substrs:  []string{"foo"},
			expected: false,
		},
		{
			name:     "empty substrs",
			s:        "foo bar",
			substrs:  []string{},
			expected: false,
		},
		{
			name:     "contains first substr",
			s:        "foo bar baz",
			substrs:  []string{"foo", "qux"},
			expected: true,
		},
		{
			name:     "contains last substr",
			s:        "foo bar baz",
			substrs:  []string{"qux", "baz"},
			expected: true,
		},
		{
			name:     "case insensitive match",
			s:        "FOO BAR BAZ",
			substrs:  []string{"foo"},
			expected: true,
		},
		{
			name:     "no match",
			s:        "foo bar baz",
			substrs:  []string{"qux", "quux"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsAny(tt.s, tt.substrs...)
			if got != tt.expected {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, got, tt.expected)
			}
		})
	}
}
