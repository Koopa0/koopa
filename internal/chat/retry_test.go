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
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "rate limit error",
			err:  errors.New("rate limit exceeded"),
			want: true,
		},
		{
			name: "quota exceeded error",
			err:  errors.New("quota exceeded for project"),
			want: true,
		},
		{
			name: "429 status code",
			err:  errors.New("HTTP 429: Too Many Requests"),
			want: true,
		},
		{
			name: "500 server error",
			err:  errors.New("HTTP 500 Internal Server Error"),
			want: true,
		},
		{
			name: "502 bad gateway",
			err:  errors.New("502 Bad Gateway"),
			want: true,
		},
		{
			name: "503 unavailable",
			err:  errors.New("503 Service Unavailable"),
			want: true,
		},
		{
			name: "504 gateway timeout",
			err:  errors.New("504 Gateway Timeout"),
			want: true,
		},
		{
			name: "unavailable keyword",
			err:  errors.New("service unavailable"),
			want: true,
		},
		{
			name: "connection reset",
			err:  errors.New("connection reset by peer"),
			want: true,
		},
		{
			name: "timeout error",
			err:  errors.New("request timeout"),
			want: true,
		},
		{
			name: "temporary error",
			err:  errors.New("temporary failure"),
			want: true,
		},
		{
			name: "non-retryable error",
			err:  errors.New("invalid API key"),
			want: false,
		},
		{
			name: "non-retryable 400 error",
			err:  errors.New("HTTP 400 Bad Request"),
			want: false,
		},
		{
			name: "non-retryable 401 error",
			err:  errors.New("HTTP 401 Unauthorized"),
			want: false,
		},
		{
			name: "non-retryable 403 error",
			err:  errors.New("HTTP 403 Forbidden"),
			want: false,
		},
		{
			name: "case insensitive rate limit",
			err:  errors.New("RATE LIMIT reached"),
			want: true,
		},
		{
			name: "case insensitive timeout",
			err:  errors.New("TIMEOUT occurred"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := retryableError(tt.err)
			if got != tt.want {
				t.Errorf("retryableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       string
		substrs []string
		want    bool
	}{
		{
			name:    "empty string",
			s:       "",
			substrs: []string{"foo"},
			want:    false,
		},
		{
			name:    "empty substrs",
			s:       "foo bar",
			substrs: []string{},
			want:    false,
		},
		{
			name:    "contains first substr",
			s:       "foo bar baz",
			substrs: []string{"foo", "qux"},
			want:    true,
		},
		{
			name:    "contains last substr",
			s:       "foo bar baz",
			substrs: []string{"qux", "baz"},
			want:    true,
		},
		{
			name:    "case insensitive match",
			s:       "FOO BAR BAZ",
			substrs: []string{"foo"},
			want:    true,
		},
		{
			name:    "no match",
			s:       "foo bar baz",
			substrs: []string{"qux", "quux"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsAny(tt.s, tt.substrs...)
			if got != tt.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, got, tt.want)
			}
		})
	}
}
