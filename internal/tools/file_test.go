package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/security"
)

// TestFileToolsRegistration tests that file tools are registered
func TestFileToolsRegistration(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	g := genkit.Init(ctx)
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("registerFileTools panicked: %v", r)
		}
	}()

	handler := NewHandler(pathVal, security.NewCommand(), security.NewHTTP(), security.NewEnv())
	registerFileTools(g, handler)
}

// TestFileToolsWithSecurityValidator tests that path validation works
func TestFileToolsWithSecurityValidator(t *testing.T) {
	tmpDir := t.TempDir()

	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Test that validator can validate paths in allowed directory
	testFile := filepath.Join(tmpDir, "test.txt")
	validated, err := pathVal.Validate(testFile)
	if err != nil {
		t.Errorf("path validation failed for allowed path: %v", err)
	}
	if validated != testFile {
		t.Errorf("expected validated path %s, got %s", testFile, validated)
	}

	// Test that validator blocks paths outside allowed directory
	_, err = pathVal.Validate("/etc/passwd")
	if err == nil {
		t.Error("expected error for path outside allowed directory, got none")
	}
}

// TestFileOperations tests basic file operations with security
func TestFileOperations(t *testing.T) {
	tmpDir := t.TempDir()

	// Test write and read
	testFile := filepath.Join(tmpDir, "test_write.txt")
	testContent := "Hello, World!"

	// Write file
	err := os.WriteFile(testFile, []byte(testContent), 0o600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Read file
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("expected content %q, got %q", testContent, string(content))
	}

	// Test list directory
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	found := false
	for _, entry := range entries {
		if entry.Name() == "test_write.txt" {
			found = true
			break
		}
	}

	if !found {
		t.Error("written file not found in directory listing")
	}

	// Test file info
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("failed to get file info: %v", err)
	}

	if info.Name() != "test_write.txt" {
		t.Errorf("expected file name test_write.txt, got %s", info.Name())
	}

	if info.Size() != int64(len(testContent)) {
		t.Errorf("expected file size %d, got %d", len(testContent), info.Size())
	}

	// Test delete file
	err = os.Remove(testFile)
	if err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}

	// Verify file is deleted
	_, err = os.Stat(testFile)
	if !os.IsNotExist(err) {
		t.Error("file should not exist after deletion")
	}
}

// TestDirectoryOperations tests directory-related operations
func TestDirectoryOperations(t *testing.T) {
	tmpDir := t.TempDir()

	// Test creating nested directories
	nestedDir := filepath.Join(tmpDir, "level1", "level2", "level3")
	err := os.MkdirAll(nestedDir, 0o750)
	if err != nil {
		t.Fatalf("failed to create nested directories: %v", err)
	}

	// Verify directories were created
	info, err := os.Stat(nestedDir)
	if err != nil {
		t.Fatalf("nested directory not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("expected path to be a directory")
	}

	// Test permissions
	perm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o750)
	if perm != expectedPerm {
		t.Errorf("expected permissions %o, got %o", expectedPerm, perm)
	}
}

// TestFilePermissions tests that files are created with secure permissions
func TestFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "secure_file.txt")

	// Create file with 0600 permissions (owner read/write only)
	err := os.WriteFile(testFile, []byte("secure content"), 0o600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("failed to get file info: %v", err)
	}

	perm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o600)
	if perm != expectedPerm {
		t.Errorf("expected permissions %o, got %o", expectedPerm, perm)
	}
}

// TestFileEdgeCases tests edge cases in file operations
func TestFileEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// Test empty file
	emptyFile := filepath.Join(tmpDir, "empty.txt")
	err := os.WriteFile(emptyFile, []byte(""), 0o600)
	if err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	content, err := os.ReadFile(emptyFile)
	if err != nil {
		t.Fatalf("failed to read empty file: %v", err)
	}

	if len(content) != 0 {
		t.Errorf("expected empty content, got %d bytes", len(content))
	}

	// Test large file
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	largeFile := filepath.Join(tmpDir, "large.bin")
	err = os.WriteFile(largeFile, largeContent, 0o600)
	if err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}

	readContent, err := os.ReadFile(largeFile)
	if err != nil {
		t.Fatalf("failed to read large file: %v", err)
	}

	if len(readContent) != len(largeContent) {
		t.Errorf("expected %d bytes, got %d bytes", len(largeContent), len(readContent))
	}
}

// TestPathTraversalPrevention tests that path traversal is prevented
func TestPathTraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	// Test common path traversal attempts
	attacks := []string{
		"../../../etc/passwd",
		filepath.Join(tmpDir, "..", "..", "etc", "passwd"),
	}

	for _, attack := range attacks {
		_, err := pathVal.Validate(attack)
		if err == nil {
			t.Errorf("path traversal attack %q was not blocked", attack)
		}
	}
}

// BenchmarkFileRead benchmarks file read operation
func BenchmarkFileRead(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "benchmark.txt")
	content := []byte("benchmark test content")

	err := os.WriteFile(testFile, content, 0o600)
	if err != nil {
		b.Fatalf("failed to create test file: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = os.ReadFile(testFile)
	}
}

// BenchmarkFileWrite benchmarks file write operation
func BenchmarkFileWrite(b *testing.B) {
	tmpDir := b.TempDir()
	content := []byte("benchmark test content")

	b.ResetTimer()
	for i := range b.N {
		testFile := filepath.Join(tmpDir, "benchmark_"+string(rune(i))+".txt")
		_ = os.WriteFile(testFile, content, 0o600)
	}
}
