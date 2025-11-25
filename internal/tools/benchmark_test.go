package tools

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/security"
)

// Performance Expectations (from TESTING_STRATEGY_v3.md):
// - ReadFile (1MB): < 50ms

// BenchmarkFileToolset_ReadFile benchmarks reading a small file.
// Run with: go test -bench=BenchmarkFileToolset_ReadFile -benchmem ./internal/tools/...
func BenchmarkFileToolset_ReadFile(b *testing.B) {
	tmpDir := b.TempDir()
	// Resolve symlinks for macOS (/var -> /private/var)
	realTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	if realTmpDir == "" {
		realTmpDir = tmpDir
	}

	testFile := realTmpDir + "/small.txt"

	// Create a small test file (1KB)
	content := strings.Repeat("Hello World! ", 100)
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	toolset, err := setupBenchmarkFileToolset(b, realTmpDir)
	if err != nil {
		b.Fatalf("Failed to setup toolset: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := toolset.ReadFile(ctx, ReadFileInput{Path: testFile})
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
		if result.Status == StatusError {
			b.Fatalf("ReadFile returned error status: %v", result.Error)
		}
	}
}

// BenchmarkFileToolset_ReadFile_Medium benchmarks reading a medium file (100KB).
func BenchmarkFileToolset_ReadFile_Medium(b *testing.B) {
	tmpDir := b.TempDir()
	realTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	if realTmpDir == "" {
		realTmpDir = tmpDir
	}

	testFile := realTmpDir + "/medium.txt"

	// Create a 100KB test file
	content := strings.Repeat("This is a test line for benchmarking file reads. ", 2000)
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	toolset, err := setupBenchmarkFileToolset(b, realTmpDir)
	if err != nil {
		b.Fatalf("Failed to setup toolset: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := toolset.ReadFile(ctx, ReadFileInput{Path: testFile})
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
		if result.Status == StatusError {
			b.Fatalf("ReadFile returned error status: %v", result.Error)
		}
	}
}

// BenchmarkFileToolset_ReadFile_Large benchmarks reading a large file (1MB).
func BenchmarkFileToolset_ReadFile_Large(b *testing.B) {
	tmpDir := b.TempDir()
	realTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	if realTmpDir == "" {
		realTmpDir = tmpDir
	}

	testFile := realTmpDir + "/large.txt"

	// Create a 1MB test file
	content := strings.Repeat("This is a benchmark test line for measuring large file read performance. ", 13000)
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	toolset, err := setupBenchmarkFileToolset(b, realTmpDir)
	if err != nil {
		b.Fatalf("Failed to setup toolset: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := toolset.ReadFile(ctx, ReadFileInput{Path: testFile})
		if err != nil {
			b.Fatalf("ReadFile failed: %v", err)
		}
		if result.Status == StatusError {
			b.Fatalf("ReadFile returned error status: %v", result.Error)
		}
	}
}

// BenchmarkFileToolset_GetFileInfo benchmarks getting file info.
func BenchmarkFileToolset_GetFileInfo(b *testing.B) {
	tmpDir := b.TempDir()
	realTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	if realTmpDir == "" {
		realTmpDir = tmpDir
	}

	testFile := realTmpDir + "/info.txt"

	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	toolset, err := setupBenchmarkFileToolset(b, realTmpDir)
	if err != nil {
		b.Fatalf("Failed to setup toolset: %v", err)
	}

	ctx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := toolset.GetFileInfo(ctx, GetFileInfoInput{Path: testFile})
		if err != nil {
			b.Fatalf("GetFileInfo failed: %v", err)
		}
		if result.Status == StatusError {
			b.Fatalf("GetFileInfo returned error status: %v", result.Error)
		}
	}
}

// BenchmarkPathValidation benchmarks path validation.
func BenchmarkPathValidation(b *testing.B) {
	tmpDir := b.TempDir()
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		b.Fatalf("Failed to create path validator: %v", err)
	}

	testPath := tmpDir + "/test/nested/path/file.txt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pathVal.Validate(testPath)
	}
}

// BenchmarkPathValidation_Malicious benchmarks path validation with malicious paths.
func BenchmarkPathValidation_Malicious(b *testing.B) {
	tmpDir := b.TempDir()
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		b.Fatalf("Failed to create path validator: %v", err)
	}

	maliciousPaths := []string{
		"../../../etc/passwd",
		tmpDir + "/../../../etc/passwd",
		"/etc/passwd",
		tmpDir + "/safe/../../../etc/passwd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := maliciousPaths[i%len(maliciousPaths)]
		_, _ = pathVal.Validate(path)
	}
}

// setupBenchmarkFileToolset creates a FileToolset for benchmarking.
func setupBenchmarkFileToolset(b *testing.B, tmpDir string) (*FileToolset, error) {
	b.Helper()

	// Resolve symlinks to get the real path (macOS /var -> /private/var)
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		realTmpDir = tmpDir // fallback
	}

	pathVal, err := security.NewPath([]string{realTmpDir})
	if err != nil {
		return nil, err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewFileToolset(pathVal, logger)
}
