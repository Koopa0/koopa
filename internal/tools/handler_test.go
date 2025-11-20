package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/security"
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

// resolveSymlinks resolves symlinks for macOS compatibility
// macOS t.TempDir() returns /var/folders/... which is actually a symlink to /private/var/folders/...
func resolveSymlinks(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("failed to resolve symlinks for %s: %v", path, err)
	}
	return resolved
}

// TestNewHandler tests Handler creation
func TestNewHandler(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cmdVal := security.NewCommand()
	httpVal := security.NewHTTP()
	envVal := security.NewEnv()

	handler := NewHandler(pathVal, cmdVal, httpVal, envVal, nil)
	if handler == nil {
		t.Fatal("NewHandler returned nil")
		return
	}

	if handler.pathVal == nil || handler.cmdVal == nil ||
		handler.httpVal == nil || handler.envVal == nil {
		t.Error("Handler has nil validators")
	}
}

// File Operations Tests

func TestHandler_ReadFile(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv(), nil)

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(testContent), 0o600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		want      string
		shouldErr bool
	}{
		{
			name:      "read existing file",
			path:      testFile,
			want:      testContent,
			shouldErr: false,
		},
		{
			name:      "read non-existent file",
			path:      filepath.Join(tmpDir, "nonexistent.txt"),
			shouldErr: true,
		},
		{
			name:      "path traversal attempt",
			path:      "../../../etc/passwd",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := handler.ReadFile(tt.path)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestHandler_WriteFile(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv(), nil)

	tests := []struct {
		name      string
		path      string
		content   string
		shouldErr bool
	}{
		{
			name:      "write new file",
			path:      filepath.Join(tmpDir, "new.txt"),
			content:   "test content",
			shouldErr: false,
		},
		{
			name:      "write with nested directories",
			path:      filepath.Join(tmpDir, "nested", "dir", "file.txt"),
			content:   "nested content",
			shouldErr: false,
		},
		{
			name:      "overwrite existing file",
			path:      filepath.Join(tmpDir, "overwrite.txt"),
			content:   "new content",
			shouldErr: false,
		},
		{
			name:      "path traversal attempt",
			path:      "../../../tmp/malicious.txt",
			content:   "malicious",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.WriteFile(tt.path, tt.content)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !strings.Contains(result, "successfully wrote file") {
					t.Errorf("unexpected result: %s", result)
				}

				// Verify file was actually written
				content, readErr := os.ReadFile(tt.path)
				if readErr != nil {
					t.Errorf("failed to read written file: %v", readErr)
				}
				if string(content) != tt.content {
					t.Errorf("written content %q != expected %q", string(content), tt.content)
				}
			}
		})
	}
}

func TestHandler_ListFiles(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv(), nil)

	// Create test files and directories
	_ = os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0o600)
	_ = os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("test"), 0o600)
	_ = os.Mkdir(filepath.Join(tmpDir, "subdir"), 0o750)

	tests := []struct {
		name      string
		path      string
		contains  []string
		shouldErr bool
	}{
		{
			name:      "list directory",
			path:      tmpDir,
			contains:  []string{"[File] file1.txt", "[File] file2.txt", "[Directory] subdir"},
			shouldErr: false,
		},
		{
			name:      "list non-existent directory",
			path:      filepath.Join(tmpDir, "nonexistent"),
			shouldErr: true,
		},
		{
			name:      "path traversal attempt",
			path:      "../../../etc",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.ListFiles(tt.path)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				for _, expected := range tt.contains {
					if !strings.Contains(result, expected) {
						t.Errorf("result %q does not contain %q", result, expected)
					}
				}
			}
		})
	}
}

func TestHandler_DeleteFile(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv(), nil)

	tests := []struct {
		name      string
		setup     func() string // Returns path to delete
		shouldErr bool
	}{
		{
			name: "delete existing file",
			setup: func() string {
				path := filepath.Join(tmpDir, "delete_me.txt")
				_ = os.WriteFile(path, []byte("test"), 0o600)
				return path
			},
			shouldErr: false,
		},
		{
			name: "delete non-existent file",
			setup: func() string {
				return filepath.Join(tmpDir, "nonexistent.txt")
			},
			shouldErr: true,
		},
		{
			name: "path traversal attempt",
			setup: func() string {
				return "../../../tmp/file.txt"
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			result, err := handler.DeleteFile(path)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !strings.Contains(result, "successfully deleted file") {
					t.Errorf("unexpected result: %s", result)
				}

				// Verify file was actually deleted
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Error("file should not exist after deletion")
				}
			}
		})
	}
}

func TestHandler_GetFileInfo(t *testing.T) {
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv(), nil)

	// Create test file
	testFile := filepath.Join(tmpDir, "info.txt")
	testContent := "test content for info"
	_ = os.WriteFile(testFile, []byte(testContent), 0o600)

	// Create test directory
	testDir := filepath.Join(tmpDir, "testdir")
	_ = os.Mkdir(testDir, 0o750)

	tests := []struct {
		name      string
		path      string
		contains  []string
		shouldErr bool
	}{
		{
			name:      "get file info",
			path:      testFile,
			contains:  []string{"Name:", "Size:", "Is directory: false", "Modified time:", "Permissions:"},
			shouldErr: false,
		},
		{
			name:      "get directory info",
			path:      testDir,
			contains:  []string{"Name:", "Is directory: true", "Permissions:"},
			shouldErr: false,
		},
		{
			name:      "get info for non-existent file",
			path:      filepath.Join(tmpDir, "nonexistent"),
			shouldErr: true,
		},
		{
			name:      "path traversal attempt",
			path:      "../../../etc/passwd",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GetFileInfo(tt.path)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				for _, expected := range tt.contains {
					if !strings.Contains(result, expected) {
						t.Errorf("result %q does not contain %q", result, expected)
					}
				}
			}
		})
	}
}

// System Operations Tests

func TestHandler_CurrentTime(t *testing.T) {
	handler := NewHandler(nil, nil, nil, nil, nil)

	result, err := handler.CurrentTime()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check format: "2006-01-02 15:04:05 (Monday)"
	if !strings.Contains(result, "-") {
		t.Error("result should contain date separators")
	}
	if !strings.Contains(result, ":") {
		t.Error("result should contain time separators")
	}
	if !strings.Contains(result, "(") || !strings.Contains(result, ")") {
		t.Error("result should contain day of week in parentheses")
	}
}

func TestHandler_ExecuteCommand(t *testing.T) {
	cmdVal := security.NewCommand()
	handler := NewHandler(nil, cmdVal, nil, nil, nil)

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
		contains  string
	}{
		{
			name:      "safe command echo",
			command:   "echo",
			args:      []string{"hello"},
			shouldErr: false,
			contains:  "hello",
		},
		{
			name:      "dangerous command rm -rf",
			command:   "rm",
			args:      []string{"-rf", "/"},
			shouldErr: true,
		},
		{
			name:      "command injection attempt",
			command:   "ls",
			args:      []string{"; rm -rf /"},
			shouldErr: true,
		},
		{
			name:      "sudo su blocked",
			command:   "sudo",
			args:      []string{"su"},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.ExecuteCommand(context.Background(), tt.command, tt.args)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.contains != "" && !strings.Contains(result, tt.contains) {
					t.Errorf("result %q does not contain %q", result, tt.contains)
				}
			}
		})
	}
}

func TestHandler_GetEnv(t *testing.T) {
	envVal := security.NewEnv()
	handler := NewHandler(nil, nil, nil, envVal, nil)

	// Set test environment variable
	testKey := "TEST_SAFE_VAR"
	testValue := "test value"
	_ = os.Setenv(testKey, testValue)
	defer func() { _ = os.Unsetenv(testKey) }()

	tests := []struct {
		name      string
		envVar    string
		want      string
		shouldErr bool
	}{
		{
			name:      "get safe variable",
			envVar:    testKey,
			want:      testValue,
			shouldErr: false,
		},
		{
			name:      "get non-existent variable",
			envVar:    "NONEXISTENT_VAR_XYZ",
			want:      "is not set or is empty",
			shouldErr: false,
		},
		{
			name:      "blocked API_KEY",
			envVar:    "API_KEY",
			shouldErr: true,
		},
		{
			name:      "blocked SECRET",
			envVar:    "MY_SECRET",
			shouldErr: true,
		},
		{
			name:      "blocked TOKEN",
			envVar:    "AUTH_TOKEN",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.GetEnv(tt.envVar)
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !strings.Contains(result, tt.want) {
					t.Errorf("result %q does not contain %q", result, tt.want)
				}
			}
		})
	}
}

// Network Operations Tests

func TestHandler_HTTPGet_SSRF_Protection(t *testing.T) {
	// Use real security.HTTP to test SSRF protection
	httpVal := security.NewHTTP()
	handler := NewHandler(nil, nil, httpVal, nil, nil)

	tests := []struct {
		name   string
		url    string
		reason string
	}{
		{
			name:   "private IP blocked",
			url:    "http://192.168.1.1",
			reason: "SSRF protection blocks private IPs",
		},
		{
			name:   "metadata endpoint blocked",
			url:    "http://169.254.169.254",
			reason: "SSRF protection blocks cloud metadata",
		},
		{
			name:   "localhost blocked",
			url:    "http://localhost:8080",
			reason: "SSRF protection blocks localhost",
		},
		{
			name:   "127.0.0.1 blocked",
			url:    "http://127.0.0.1:8080",
			reason: "SSRF protection blocks loopback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.HTTPGet(tt.url)
			if err == nil {
				t.Errorf("expected error for %s (%s), got none", tt.url, tt.reason)
			}
		})
	}
}

func TestHandler_HTTPGet_Success(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		maxSize        int64
		expectContains []string
	}{
		{
			name:           "successful GET request",
			statusCode:     200,
			responseBody:   "Hello, World!",
			maxSize:        5 * 1024 * 1024,
			expectContains: []string{`"status":200`, `"body":"Hello, World!"`},
		},
		{
			name:           "404 not found",
			statusCode:     404,
			responseBody:   "Not Found",
			maxSize:        5 * 1024 * 1024,
			expectContains: []string{`"status":404`, `"body":"Not Found"`},
		},
		{
			name:           "JSON response",
			statusCode:     200,
			responseBody:   `{"key":"value"}`,
			maxSize:        5 * 1024 * 1024,
			expectContains: []string{`"status":200`, `"body":"{\"key\":\"value\"}"`},
		},
		{
			name:           "empty response",
			statusCode:     204,
			responseBody:   "",
			maxSize:        5 * 1024 * 1024,
			expectContains: []string{`"status":204`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock HTTP server for this test
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET request, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create mock validator that allows the mock server URL
			mockVal := &mockHTTPValidator{
				validateErr: nil, // Allow the URL
				client:      server.Client(),
				maxSize:     tt.maxSize,
			}

			handler := NewHandler(nil, nil, mockVal, nil, nil)

			result, err := handler.HTTPGet(server.URL)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify result contains expected strings
			for _, expected := range tt.expectContains {
				if !strings.Contains(result, expected) {
					t.Errorf("result %q does not contain %q", result, expected)
				}
			}
		})
	}
}

func TestHandler_HTTPGet_ResponseSizeLimit(t *testing.T) {
	// Create server with large response
	largeContent := strings.Repeat("A", 10*1024*1024) // 10MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, largeContent)
	}))
	defer server.Close()

	// Create mock validator with small size limit
	mockVal := &mockHTTPValidator{
		validateErr: nil,
		client:      server.Client(),
		maxSize:     1 * 1024 * 1024, // 1MB limit
	}

	handler := NewHandler(nil, nil, mockVal, nil, nil)

	_, err := handler.HTTPGet(server.URL)
	if err == nil {
		t.Error("expected error for response exceeding size limit, got none")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestHandler_HTTPGet_ValidationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create mock validator that rejects the URL
	mockVal := &mockHTTPValidator{
		validateErr: io.ErrUnexpectedEOF, // Any error
		client:      server.Client(),
	}

	handler := NewHandler(nil, nil, mockVal, nil, nil)

	_, err := handler.HTTPGet(server.URL)
	if err == nil {
		t.Error("expected validation error, got none")
	}
	if !strings.Contains(err.Error(), "url validation failed") {
		t.Errorf("expected validation error message, got: %v", err)
	}
}

// Benchmark Tests

func BenchmarkHandler_ReadFile(b *testing.B) {
	tmpDir := b.TempDir()
	pathVal, _ := security.NewPath([]string{tmpDir})
	handler := NewHandler(pathVal, nil, nil, nil, nil)

	testFile := filepath.Join(tmpDir, "bench.txt")
	_ = os.WriteFile(testFile, []byte("benchmark test content"), 0o600)

	b.ResetTimer()
	for b.Loop() {
		_, _ = handler.ReadFile(testFile)
	}
}

func BenchmarkHandler_CurrentTime(b *testing.B) {
	handler := NewHandler(nil, nil, nil, nil, nil)

	b.ResetTimer()
	for b.Loop() {
		_, _ = handler.CurrentTime()
	}
}

func BenchmarkHandler_ExecuteCommand(b *testing.B) {
	cmdVal := security.NewCommand()
	handler := NewHandler(nil, cmdVal, nil, nil, nil)

	b.ResetTimer()
	for b.Loop() {
		_, _ = handler.ExecuteCommand(context.Background(), "echo", []string{"test"})
	}
}
