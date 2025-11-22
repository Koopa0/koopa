package tools

import (
	"net/http"
	"path/filepath"
	"testing"
)

// mockHTTPValidator is a mock implementation of HTTPValidator for testing.
// Follows Go testing best practices: simple, explicit mocks without external libraries.
type mockHTTPValidator struct {
	validateErr error
	client      *http.Client
	maxSize     int64
}

func (m *mockHTTPValidator) ValidateURL(url string) error {
	return m.validateErr
}

func (m *mockHTTPValidator) Client() *http.Client {
	if m.client != nil {
		return m.client
	}
	// Return a default client if not set
	return &http.Client{}
}

func (m *mockHTTPValidator) MaxResponseSize() int64 {
	if m.maxSize > 0 {
		return m.maxSize
	}
	// Default 5MB
	return 5 * 1024 * 1024
}

// resolveSymlinks resolves symlinks for macOS compatibility.
// macOS t.TempDir() returns /var/folders/... which is actually a symlink to /private/var/folders/...
func resolveSymlinks(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("failed to resolve symlinks for %s: %v", path, err)
	}
	return resolved
}
