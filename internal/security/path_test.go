package security

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathValidation tests path validation security
func TestPathValidation(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Change to temp directory for testing
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}
	defer func() { _ = os.Chdir(workDir) }() // Restore original directory

	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		shouldErr bool
		reason    string
	}{
		{
			name:      "valid relative path",
			path:      "test.txt",
			shouldErr: false,
			reason:    "relative path in working directory should be allowed",
		},
		{
			name:      "valid absolute path in allowed dir",
			path:      filepath.Join(tmpDir, "test.txt"),
			shouldErr: false,
			reason:    "absolute path in allowed directory should be allowed",
		},
		{
			name:      "path traversal attempt",
			path:      "../../../etc/passwd",
			shouldErr: true,
			reason:    "path traversal should be blocked",
		},
		{
			name:      "absolute path outside allowed dirs",
			path:      "/etc/passwd",
			shouldErr: true,
			reason:    "absolute path outside allowed directories should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(tt.path)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %s, but got none: %s", tt.path, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %s: %v (%s)", tt.path, err, tt.reason)
			}
		})
	}
}

// TestPathErrorSanitization tests that error messages don't leak sensitive paths
func TestPathErrorSanitization(t *testing.T) {
	validator, err := NewPath([]string{})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Try to access a path outside allowed directories
	if _, err = validator.Validate("/etc/passwd"); err == nil {
		t.Fatal("expected error for /etc/passwd")
	}

	// Error message should not contain the full path
	errMsg := err.Error()
	if strings.Contains(errMsg, "/etc/passwd") {
		t.Errorf("error message leaks sensitive path: %s", errMsg)
	}

	// Error should contain generic message
	if !strings.Contains(errMsg, "outside allowed directories") {
		t.Errorf("error message should contain generic message, got: %s", errMsg)
	}
}

// TestIsPathSafe tests quick path safety check
func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		path string
		safe bool
	}{
		{"file.txt", true},
		{"../etc/passwd", false},      // Contains "../"
		{"/etc/passwd", false},        // Contains "/etc/"
		{"../../secret", false},       // Contains "../"
		{"/home/user/file.txt", true}, // Safe absolute path
	}

	for _, tt := range tests {
		if result := IsPathSafe(tt.path); result != tt.safe {
			t.Errorf("IsPathSafe(%q) = %v, want %v", tt.path, result, tt.safe)
		}
	}
}

// TestSymlinkValidation tests symlink handling
func TestSymlinkValidation(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Change to temp directory for testing
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}
	defer func() { _ = os.Chdir(workDir) }() // Restore original directory

	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Create a file
	targetFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	// Create a symlink to the file
	symlinkPath := filepath.Join(tmpDir, "symlink.txt")
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Skipf("symlink creation not supported on this platform: %v", err)
	}

	// Validate symlink path (should resolve to target and pass)
	resolvedPath, err := validator.Validate(symlinkPath)
	if err != nil {
		t.Errorf("symlink validation failed: %v", err)
	}

	// Compare resolved paths (handle /var vs /private/var on macOS)
	expectedPath, err := filepath.EvalSymlinks(targetFile)
	if err != nil {
		expectedPath = targetFile
	}
	if resolvedPath != expectedPath {
		t.Errorf("expected resolved path %s, got %s", expectedPath, resolvedPath)
	}
}

// TestPathValidationWithNonExistentFile tests validation of non-existent files
func TestPathValidationWithNonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}
	defer func() { _ = os.Chdir(workDir) }()

	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Test with non-existent file (should be allowed for creating new files)
	nonExistentPath := filepath.Join(tmpDir, "nonexistent.txt")
	validatedPath, err := validator.Validate(nonExistentPath)
	if err != nil {
		t.Errorf("validation of non-existent file failed: %v", err)
	}
	if validatedPath != nonExistentPath {
		t.Errorf("expected path %s, got %s", nonExistentPath, validatedPath)
	}
}

// TestSymlinkBypassAttempt tests that symlinks pointing outside allowed dirs are blocked
func TestSymlinkBypassAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Create another temp directory outside the allowed directory
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret data"), 0o644); err != nil {
		t.Fatalf("failed to create outside file: %v", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}
	defer func() { _ = os.Chdir(workDir) }()

	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Create symlink inside allowed dir pointing to file outside
	symlinkPath := filepath.Join(tmpDir, "bypass.txt")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	// Try to validate the symlink (should fail because it points outside)
	_, err = validator.Validate(symlinkPath)
	if err == nil {
		t.Error("expected error for symlink pointing outside allowed dirs, but got none")
	}

	if err != nil && !errors.Is(err, ErrSymlinkOutsideAllowed) {
		t.Errorf("expected ErrSymlinkOutsideAllowed, got: %v", err)
	}
}

// TestPathValidationErrors tests error conditions in path validation
func TestPathValidationErrors(t *testing.T) {
	tmpDir := t.TempDir()
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}
	defer func() { _ = os.Chdir(workDir) }()

	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Test with extremely long path (should be handled gracefully)
	longPath := filepath.Join(tmpDir, string(make([]byte, 1000)))
	_, err = validator.Validate(longPath)
	// Should not panic, error is acceptable
	_ = err
}

// TestGetHomeDir tests home directory retrieval
func TestGetHomeDir(t *testing.T) {
	homeDir, err := GetHomeDir()
	if err != nil {
		t.Errorf("GetHomeDir() returned error: %v", err)
	}
	if homeDir == "" {
		t.Error("GetHomeDir() returned empty string")
	}
}

// BenchmarkPathValidation benchmarks path validation performance
func BenchmarkPathValidation(b *testing.B) {
	validator, err := NewPath([]string{})
	if err != nil {
		b.Fatalf("failed to create path validator: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = validator.Validate("test.txt")
	}
}
