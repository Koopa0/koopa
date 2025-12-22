package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			require.NoError(t, err, "ReadFile should not return Go error")
			assert.Equal(t, tt.wantStatus, result.Status)
			require.NotNil(t, result.Error, "result.Error should not be nil for security errors")
			assert.Equal(t, tt.wantErrCode, result.Error.Code)
			assert.Contains(t, result.Error.Message, "path validation failed")
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

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)
	assert.Nil(t, result.Error)

	// Verify content is returned
	data, ok := result.Data.(map[string]any)
	require.True(t, ok, "result.Data should be a map")
	assert.Equal(t, testContent, data["content"])
}

func TestFileTools_ReadFile_NotFound(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Try to read non-existent file within allowed directory
	nonExistentPath := filepath.Join(h.tempDir, "does-not-exist.txt")

	result, err := ft.ReadFile(nil, ReadFileInput{Path: nonExistentPath})

	require.NoError(t, err, "ReadFile should not return Go error")
	assert.Equal(t, StatusError, result.Status)
	require.NotNil(t, result.Error)
	assert.Equal(t, ErrCodeNotFound, result.Error.Code)
}

func TestFileTools_ReadFile_FileTooLarge(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a file larger than MaxReadFileSize (10MB)
	largePath := filepath.Join(h.tempDir, "large.txt")
	f, err := os.Create(largePath)
	require.NoError(t, err)

	// Write 11MB of data
	_, err = f.Write(make([]byte, MaxReadFileSize+1024*1024))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	result, err := ft.ReadFile(nil, ReadFileInput{Path: largePath})

	require.NoError(t, err, "ReadFile should not return Go error")
	assert.Equal(t, StatusError, result.Status)
	require.NotNil(t, result.Error)
	assert.Equal(t, ErrCodeValidation, result.Error.Code)
	assert.Contains(t, result.Error.Message, "exceeds maximum")
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

			require.NoError(t, err, "WriteFile should not return Go error")
			assert.Equal(t, tt.wantStatus, result.Status)
			require.NotNil(t, result.Error)
			assert.Equal(t, tt.wantErrCode, result.Error.Code)
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

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)
	assert.Nil(t, result.Error)

	// Verify file was actually written
	content, err := os.ReadFile(testPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
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

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)

	// Verify file was created
	content, err := os.ReadFile(nestedPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
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

			require.NoError(t, err, "DeleteFile should not return Go error")
			assert.Equal(t, tt.wantStatus, result.Status)
			require.NotNil(t, result.Error)
			assert.Equal(t, tt.wantErrCode, result.Error.Code)
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
	_, err := os.Stat(testPath)
	require.NoError(t, err)

	result, err := ft.DeleteFile(nil, DeleteFileInput{Path: testPath})

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)

	// Verify file was deleted
	_, err = os.Stat(testPath)
	assert.True(t, os.IsNotExist(err), "file should be deleted")
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

			require.NoError(t, err, "ListFiles should not return Go error")
			assert.Equal(t, tt.wantStatus, result.Status)
			require.NotNil(t, result.Error)
			assert.Equal(t, tt.wantErrCode, result.Error.Code)
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
	require.NoError(t, os.Mkdir(subDir, 0o750))

	result, err := ft.ListFiles(nil, ListFilesInput{Path: h.tempDir})

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)

	// Verify entries are returned
	data, ok := result.Data.(map[string]any)
	require.True(t, ok, "result.Data should be a map")

	// entries is []map[string]any, but type assertion gives []any
	entries := data["entries"]
	require.NotNil(t, entries, "entries should not be nil")

	// Use count field to verify
	count, ok := data["count"].(int)
	require.True(t, ok, "count should be an int")
	assert.GreaterOrEqual(t, count, 3, "should have at least 3 entries")
}

// ============================================================================
// GetFileInfo Integration Tests
// ============================================================================

func TestFileTools_GetFileInfo_PathSecurity(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	result, err := ft.GetFileInfo(nil, GetFileInfoInput{Path: "/etc/passwd"})

	require.NoError(t, err, "GetFileInfo should not return Go error")
	assert.Equal(t, StatusError, result.Status)
	require.NotNil(t, result.Error)
	assert.Equal(t, ErrCodeSecurity, result.Error.Code)
}

func TestFileTools_GetFileInfo_Success(t *testing.T) {
	t.Parallel()

	h := newfileTools(t)
	ft := h.createFileTools()

	// Create a test file
	testPath := h.createTestFile("info.txt", "test content")

	result, err := ft.GetFileInfo(nil, GetFileInfoInput{Path: testPath})

	require.NoError(t, err)
	assert.Equal(t, StatusSuccess, result.Status)

	// Verify info is returned
	data, ok := result.Data.(map[string]any)
	require.True(t, ok, "result.Data should be a map")
	assert.Equal(t, "info.txt", data["name"])
	assert.Equal(t, int64(12), data["size"]) // "test content" = 12 bytes
}
