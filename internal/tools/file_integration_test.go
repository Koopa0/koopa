package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

// fileTools provides test utilities for FileTools.
type fileTools struct {
	t       *testing.T
	tempDir string
}

func newfileTools(t *testing.T) *fileTools {
	t.Helper()
	tempDir := t.TempDir()
	// Resolve symlinks (macOS /var -> /private/var)
	realTempDir, err := filepath.EvalSymlinks(tempDir)
	if err != nil {
		t.Fatalf("failed to resolve temp dir symlinks: %v", err)
	}
	return &fileTools{t: t, tempDir: realTempDir}
}

func (h *fileTools) createFileTools() *FileTools {
	h.t.Helper()
	pathVal, err := security.NewPath([]string{h.tempDir})
	if err != nil {
		h.t.Fatalf("failed to create path validator: %v", err)
	}
	ft, err := NewFileTools(pathVal, testLogger())
	if err != nil {
		h.t.Fatalf("failed to create file tools: %v", err)
	}
	return ft
}

func (h *fileTools) createTestFile(name, content string) string {
	h.t.Helper()
	path := filepath.Join(h.tempDir, name)
	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		h.t.Fatalf("failed to create test file: %v", err)
	}
	return path
}

// ============================================================================
// ReadFile Integration Tests
// ============================================================================

func TestFileTools_ReadFile_PathSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		wantStatus  Status
		wantErrCode ErrorCode
	}{
		{
			name:        "path traversal blocked",
			path:        "../../../etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "absolute path outside allowed dirs blocked",
			path:        "/etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "double dot traversal blocked",
			path:        "foo/../../etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newfileTools(t)
			ft := h.createFileTools()

			result, err := ft.ReadFile(nil, ReadFileInput{Path: tt.path})

			// FileTools returns business errors in Result, not Go errors
			if err != nil {
				t.Fatalf("ReadFile(%q) unexpected Go error: %v (should not return Go error)", tt.path, err)
			}
			if got, want := result.Status, tt.wantStatus; got != want {
				t.Errorf("ReadFile(%q).Status = %v, want %v", tt.path, got, want)
			}
			if result.Error == nil {
				t.Fatalf("ReadFile(%q).Error = nil, want non-nil for security errors", tt.path)
			}
			if got, want := result.Error.Code, tt.wantErrCode; got != want {
				t.Errorf("ReadFile(%q).Error.Code = %v, want %v", tt.path, got, want)
			}
			if !strings.Contains(result.Error.Message, "path validation failed") {
				t.Errorf("ReadFile(%q).Error.Message = %q, want contains %q", tt.path, result.Error.Message, "path validation failed")
			}
		})
	}
}

func TestFileTools_ReadFile_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a test file
	testContent := "Hello, World!"
	testPath := h.createTestFile("test.txt", testContent)

	result, err := ft.ReadFile(nil, ReadFileInput{Path: testPath})

	if err != nil {
		t.Fatalf("ReadFile(%q) unexpected error: %v", testPath, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("ReadFile(%q).Status = %v, want %v", testPath, got, want)
	}
	if result.Error != nil {
		t.Errorf("ReadFile(%q).Error = %v, want nil", testPath, result.Error)
	}

	// Verify content is returned
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("ReadFile(%q).Data type = %T, want map[string]any", testPath, result.Data)
	}
	if got, want := data["content"], testContent; got != want {
		t.Errorf("ReadFile(%q).Data[content] = %q, want %q", testPath, got, want)
	}
}

func TestFileTools_ReadFile_NotFound(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Try to read non-existent file within allowed directory
	nonExistentPath := filepath.Join(h.tempDir, "does-not-exist.txt")

	result, err := ft.ReadFile(nil, ReadFileInput{Path: nonExistentPath})

	if err != nil {
		t.Fatalf("ReadFile(%q) unexpected Go error: %v (should not return Go error)", nonExistentPath, err)
	}
	if got, want := result.Status, StatusError; got != want {
		t.Errorf("ReadFile(%q).Status = %v, want %v", nonExistentPath, got, want)
	}
	if result.Error == nil {
		t.Fatal("ReadFile(non-existent).Error = nil, want non-nil")
	}
	if got, want := result.Error.Code, ErrCodeNotFound; got != want {
		t.Errorf("ReadFile(%q).Error.Code = %v, want %v", nonExistentPath, got, want)
	}
}

func TestFileTools_ReadFile_FileTooLarge(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a file larger than MaxReadFileSize (10MB)
	largePath := filepath.Join(h.tempDir, "large.txt")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("os.Create(%q) unexpected error: %v", largePath, err)
	}

	// Write 11MB of data
	_, err = f.Write(make([]byte, MaxReadFileSize+1024*1024))
	if err != nil {
		t.Fatalf("f.Write() unexpected error: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("f.Close() unexpected error: %v", err)
	}

	result, err := ft.ReadFile(nil, ReadFileInput{Path: largePath})

	if err != nil {
		t.Fatalf("ReadFile(%q) unexpected Go error: %v (should not return Go error)", largePath, err)
	}
	if got, want := result.Status, StatusError; got != want {
		t.Errorf("ReadFile(%q).Status = %v, want %v", largePath, got, want)
	}
	if result.Error == nil {
		t.Fatal("ReadFile(large file).Error = nil, want non-nil")
	}
	if got, want := result.Error.Code, ErrCodeValidation; got != want {
		t.Errorf("ReadFile(%q).Error.Code = %v, want %v", largePath, got, want)
	}
	if !strings.Contains(result.Error.Message, "exceeds maximum") {
		t.Errorf("ReadFile(%q).Error.Message = %q, want contains %q", largePath, result.Error.Message, "exceeds maximum")
	}
}

// ============================================================================
// WriteFile Integration Tests
// ============================================================================

func TestFileTools_WriteFile_PathSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		wantStatus  Status
		wantErrCode ErrorCode
	}{
		{
			name:        "path traversal blocked",
			path:        "../../../tmp/evil.txt",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "absolute path outside allowed dirs blocked",
			path:        "/tmp/evil.txt",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "system file blocked",
			path:        "/etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newfileTools(t)
			ft := h.createFileTools()

			result, err := ft.WriteFile(nil, WriteFileInput{
				Path:    tt.path,
				Content: "malicious content",
			})

			if err != nil {
				t.Fatalf("WriteFile(%q) unexpected Go error: %v (should not return Go error)", tt.path, err)
			}
			if got, want := result.Status, tt.wantStatus; got != want {
				t.Errorf("WriteFile(%q).Status = %v, want %v", tt.path, got, want)
			}
			if result.Error == nil {
				t.Fatalf("WriteFile(%q).Error = nil, want non-nil", tt.path)
			}
			if got, want := result.Error.Code, tt.wantErrCode; got != want {
				t.Errorf("WriteFile(%q).Error.Code = %v, want %v", tt.path, got, want)
			}
		})
	}
}

func TestFileTools_WriteFile_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	testPath := filepath.Join(h.tempDir, "new-file.txt")
	testContent := "New content"

	result, err := ft.WriteFile(nil, WriteFileInput{
		Path:    testPath,
		Content: testContent,
	})

	if err != nil {
		t.Fatalf("WriteFile(%q) unexpected error: %v", testPath, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("WriteFile(%q).Status = %v, want %v", testPath, got, want)
	}
	if result.Error != nil {
		t.Errorf("WriteFile(%q).Error = %v, want nil", testPath, result.Error)
	}

	// Verify file was actually written
	content, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) unexpected error: %v", testPath, err)
	}
	if got, want := string(content), testContent; got != want {
		t.Errorf("os.ReadFile(%q) = %q, want %q", testPath, got, want)
	}
}

func TestFileTools_WriteFile_CreatesDirectories(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Write to a nested path that doesn't exist
	nestedPath := filepath.Join(h.tempDir, "subdir", "nested", "file.txt")
	testContent := "Nested content"

	result, err := ft.WriteFile(nil, WriteFileInput{
		Path:    nestedPath,
		Content: testContent,
	})

	if err != nil {
		t.Fatalf("WriteFile(%q) unexpected error: %v", nestedPath, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("WriteFile(%q).Status = %v, want %v", nestedPath, got, want)
	}

	// Verify file was created
	content, err := os.ReadFile(nestedPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) unexpected error: %v", nestedPath, err)
	}
	if got, want := string(content), testContent; got != want {
		t.Errorf("os.ReadFile(%q) = %q, want %q", nestedPath, got, want)
	}
}

// ============================================================================
// DeleteFile Integration Tests
// ============================================================================

func TestFileTools_DeleteFile_PathSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		wantStatus  Status
		wantErrCode ErrorCode
	}{
		{
			name:        "path traversal blocked",
			path:        "../../../etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "system file blocked",
			path:        "/etc/passwd",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newfileTools(t)
			ft := h.createFileTools()

			result, err := ft.DeleteFile(nil, DeleteFileInput{Path: tt.path})

			if err != nil {
				t.Fatalf("DeleteFile(%q) unexpected Go error: %v (should not return Go error)", tt.path, err)
			}
			if got, want := result.Status, tt.wantStatus; got != want {
				t.Errorf("DeleteFile(%q).Status = %v, want %v", tt.path, got, want)
			}
			if result.Error == nil {
				t.Fatalf("DeleteFile(%q).Error = nil, want non-nil", tt.path)
			}
			if got, want := result.Error.Code, tt.wantErrCode; got != want {
				t.Errorf("DeleteFile(%q).Error.Code = %v, want %v", tt.path, got, want)
			}
		})
	}
}

func TestFileTools_DeleteFile_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a file to delete
	testPath := h.createTestFile("to-delete.txt", "content")

	// Verify file exists
	if _, err := os.Stat(testPath); err != nil {
		t.Fatalf("os.Stat(%q) unexpected error: %v (file should exist)", testPath, err)
	}

	result, err := ft.DeleteFile(nil, DeleteFileInput{Path: testPath})

	if err != nil {
		t.Fatalf("DeleteFile(%q) unexpected error: %v", testPath, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("DeleteFile(%q).Status = %v, want %v", testPath, got, want)
	}

	// Verify file was deleted
	if _, err := os.Stat(testPath); !os.IsNotExist(err) {
		t.Errorf("os.Stat(%q) after delete: file should not exist", testPath)
	}
}

// ============================================================================
// ListFiles Integration Tests
// ============================================================================

func TestFileTools_ListFiles_PathSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		wantStatus  Status
		wantErrCode ErrorCode
	}{
		{
			name:        "path traversal blocked",
			path:        "../../../etc",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
		{
			name:        "system directory blocked",
			path:        "/etc",
			wantStatus:  StatusError,
			wantErrCode: ErrCodeSecurity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newfileTools(t)
			ft := h.createFileTools()

			result, err := ft.ListFiles(nil, ListFilesInput{Path: tt.path})

			if err != nil {
				t.Fatalf("ListFiles(%q) unexpected Go error: %v (should not return Go error)", tt.path, err)
			}
			if got, want := result.Status, tt.wantStatus; got != want {
				t.Errorf("ListFiles(%q).Status = %v, want %v", tt.path, got, want)
			}
			if result.Error == nil {
				t.Fatalf("ListFiles(%q).Error = nil, want non-nil", tt.path)
			}
			if got, want := result.Error.Code, tt.wantErrCode; got != want {
				t.Errorf("ListFiles(%q).Error.Code = %v, want %v", tt.path, got, want)
			}
		})
	}
}

func TestFileTools_ListFiles_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create some test files
	h.createTestFile("file1.txt", "content1")
	h.createTestFile("file2.txt", "content2")

	// Create a subdirectory
	subDir := filepath.Join(h.tempDir, "subdir")
	if err := os.Mkdir(subDir, 0o750); err != nil {
		t.Fatalf("os.Mkdir(%q) unexpected error: %v", subDir, err)
	}

	result, err := ft.ListFiles(nil, ListFilesInput{Path: h.tempDir})

	if err != nil {
		t.Fatalf("ListFiles(%q) unexpected error: %v", h.tempDir, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("ListFiles(%q).Status = %v, want %v", h.tempDir, got, want)
	}

	// Verify entries are returned
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("ListFiles(%q).Data type = %T, want map[string]any", h.tempDir, result.Data)
	}

	// entries is []map[string]any, but type assertion gives []any
	entries := data["entries"]
	if entries == nil {
		t.Fatal("ListFiles().Data[entries] = nil, want non-nil")
	}

	// Use count field to verify
	count, ok := data["count"].(int)
	if !ok {
		t.Fatalf("ListFiles().Data[count] type = %T, want int", data["count"])
	}
	if count < 3 {
		t.Errorf("ListFiles().Data[count] = %d, want >= 3 (should have at least 3 entries)", count)
	}
}

// ============================================================================
// GetFileInfo Integration Tests
// ============================================================================

func TestFileTools_GetFileInfo_PathSecurity(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	result, err := ft.GetFileInfo(nil, GetFileInfoInput{Path: "/etc/passwd"})

	if err != nil {
		t.Fatalf("GetFileInfo(%q) unexpected Go error: %v (should not return Go error)", "/etc/passwd", err)
	}
	if got, want := result.Status, StatusError; got != want {
		t.Errorf("GetFileInfo(%q).Status = %v, want %v", "/etc/passwd", got, want)
	}
	if result.Error == nil {
		t.Fatal("GetFileInfo(/etc/passwd).Error = nil, want non-nil")
	}
	if got, want := result.Error.Code, ErrCodeSecurity; got != want {
		t.Errorf("GetFileInfo(/etc/passwd).Error.Code = %v, want %v", got, want)
	}
}

func TestFileTools_GetFileInfo_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a test file
	testPath := h.createTestFile("info.txt", "test content")

	result, err := ft.GetFileInfo(nil, GetFileInfoInput{Path: testPath})

	if err != nil {
		t.Fatalf("GetFileInfo(%q) unexpected error: %v", testPath, err)
	}
	if got, want := result.Status, StatusSuccess; got != want {
		t.Errorf("GetFileInfo(%q).Status = %v, want %v", testPath, got, want)
	}

	// Verify info is returned
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("GetFileInfo(%q).Data type = %T, want map[string]any", testPath, result.Data)
	}
	if got, want := data["name"], "info.txt"; got != want {
		t.Errorf("GetFileInfo(%q).Data[name] = %q, want %q", testPath, got, want)
	}
	if got, want := data["size"], int64(12); got != want {
		t.Errorf("GetFileInfo(%q).Data[size] = %v, want %v (test content = 12 bytes)", testPath, got, want)
	}
}
