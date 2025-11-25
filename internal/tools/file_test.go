package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileToolset_Creation tests FileToolset constructor
func TestFileToolset_Creation(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		fs, err := NewFileToolset(pathVal, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, fs)
		assert.Equal(t, FileToolsetName, fs.Name())
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		fs, err := NewFileToolset(pathVal, nil)
		assert.Error(t, err)
		assert.Nil(t, fs)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("nil path validator", func(t *testing.T) {
		t.Parallel()
		fs, err := NewFileToolset(nil, testLogger())
		assert.Error(t, err)
		assert.Nil(t, fs)
		assert.Contains(t, err.Error(), "path validator is required")
	})
}

// TestFileToolset_Tools tests tool list
func TestFileToolset_Tools(t *testing.T) {
	t.Parallel()

	pathVal, err := security.NewPath([]string{})
	require.NoError(t, err)

	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	ctx := createTestInvocationContext(t)

	tools, err := fs.Tools(ctx)
	require.NoError(t, err)
	assert.Len(t, tools, 5, "should define 5 tools")

	// Verify tool names
	toolNames := []string{"readFile", "writeFile", "listFiles", "deleteFile", "getFileInfo"}
	for _, tool := range tools {
		assert.Contains(t, toolNames, tool.Name())
		assert.NotEmpty(t, tool.Description())
	}
}

// TestFileToolset_ReadFile tests readFile tool
func TestFileToolset_ReadFile(t *testing.T) {
	t.Parallel()

	testDir := setupTestDir(t)
	testFile := filepath.Join(testDir, "test.txt")
	testContent := "Hello, World!"
	err := os.WriteFile(testFile, []byte(testContent), 0600)
	require.NoError(t, err)

	// Create FileToolset with allowed directory
	pathVal, err := security.NewPath([]string{testDir})
	require.NoError(t, err)
	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful read", func(t *testing.T) {
		result, err := fs.ReadFile(toolCtx, ReadFileInput{Path: testFile})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)
		assert.Contains(t, result.Message, "Successfully read file")

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		content, ok := dataMap["content"]
		require.True(t, ok)
		assert.Equal(t, testContent, content)

		size, ok := dataMap["size"]
		require.True(t, ok)
		assert.Equal(t, len(testContent), size)
	})

	t.Run("file not found", func(t *testing.T) {
		nonExistentFile := filepath.Join(testDir, "nonexistent.txt")
		result, err := fs.ReadFile(toolCtx, ReadFileInput{Path: nonExistentFile})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeNotFound, result.Error.Code)
	})

	t.Run("path validation failure", func(t *testing.T) {
		unauthorizedPath := "/unauthorized/path/file.txt"
		result, err := fs.ReadFile(toolCtx, ReadFileInput{Path: unauthorizedPath})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})

	t.Run("relative path resolution", func(t *testing.T) {
		// Create file in working directory
		workDir, err := os.Getwd()
		require.NoError(t, err)

		relFile := filepath.Join(workDir, "test_relative.txt")
		defer func() { _ = os.Remove(relFile) }()

		err = os.WriteFile(relFile, []byte("relative content"), 0600)
		require.NoError(t, err)

		result, err := fs.ReadFile(toolCtx, ReadFileInput{Path: "test_relative.txt"})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)
	})
}

// TestFileToolset_WriteFile tests writeFile tool
func TestFileToolset_WriteFile(t *testing.T) {
	t.Parallel()

	testDir := setupTestDir(t)
	pathVal, err := security.NewPath([]string{testDir})
	require.NoError(t, err)
	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful write new file", func(t *testing.T) {
		testFile := filepath.Join(testDir, "new_file.txt")
		testContent := "New file content"

		result, err := fs.WriteFile(toolCtx, WriteFileInput{
			Path:    testFile,
			Content: testContent,
		})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)
		assert.Contains(t, result.Message, "Successfully wrote file")

		// Verify file was created
		content, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))

		// Verify result data
		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)
		size, ok := dataMap["size"]
		require.True(t, ok)
		assert.Equal(t, len(testContent), size)
	})

	t.Run("overwrite existing file", func(t *testing.T) {
		testFile := filepath.Join(testDir, "existing.txt")

		// Create initial file
		initialContent := "initial content"
		err := os.WriteFile(testFile, []byte(initialContent), 0600)
		require.NoError(t, err)

		// Overwrite with new content
		newContent := "new content"
		result, err := fs.WriteFile(toolCtx, WriteFileInput{
			Path:    testFile,
			Content: newContent,
		})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		// Verify content was overwritten
		content, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.Equal(t, newContent, string(content))
	})

	t.Run("create nested directories", func(t *testing.T) {
		nestedFile := filepath.Join(testDir, "nested", "dir", "file.txt")

		result, err := fs.WriteFile(toolCtx, WriteFileInput{
			Path:    nestedFile,
			Content: "nested content",
		})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		// Verify file was created
		_, err = os.Stat(nestedFile)
		require.NoError(t, err)
	})

	t.Run("path validation failure", func(t *testing.T) {
		unauthorizedPath := "/unauthorized/path/file.txt"
		result, err := fs.WriteFile(toolCtx, WriteFileInput{
			Path:    unauthorizedPath,
			Content: "content",
		})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})

	t.Run("empty content", func(t *testing.T) {
		testFile := filepath.Join(testDir, "empty.txt")

		result, err := fs.WriteFile(toolCtx, WriteFileInput{
			Path:    testFile,
			Content: "",
		})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		// Verify file was created with zero bytes
		info, err := os.Stat(testFile)
		require.NoError(t, err)
		assert.Equal(t, int64(0), info.Size())
	})
}

// TestFileToolset_ListFiles tests listFiles tool
func TestFileToolset_ListFiles(t *testing.T) {
	t.Parallel()

	testDir := setupTestDir(t)

	// Create test file structure
	files := []string{
		filepath.Join(testDir, "file1.txt"),
		filepath.Join(testDir, "file2.txt"),
		filepath.Join(testDir, "subdir"),
	}
	for i, f := range files {
		if i == 2 {
			// Create directory
			err := os.Mkdir(f, 0750)
			require.NoError(t, err)
		} else {
			// Create file
			err := os.WriteFile(f, []byte("content"), 0600)
			require.NoError(t, err)
		}
	}

	pathVal, err := security.NewPath([]string{testDir})
	require.NoError(t, err)
	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful list", func(t *testing.T) {
		result, err := fs.ListFiles(toolCtx, ListFilesInput{Path: testDir})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		entries, ok := dataMap["entries"].([]map[string]any)
		require.True(t, ok)
		assert.Len(t, entries, 3)

		// Verify count
		count, ok := dataMap["count"]
		require.True(t, ok)
		assert.Equal(t, 3, count)

		// Verify file types
		var fileCount, dirCount int
		for _, entry := range entries {
			entryType, ok := entry["type"].(string)
			require.True(t, ok)
			switch entryType {
			case "file":
				fileCount++
			case "directory":
				dirCount++
			}
		}
		assert.Equal(t, 2, fileCount)
		assert.Equal(t, 1, dirCount)
	})

	t.Run("empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(testDir, "empty")
		err := os.Mkdir(emptyDir, 0750)
		require.NoError(t, err)

		result, err := fs.ListFiles(toolCtx, ListFilesInput{Path: emptyDir})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		entries, ok := dataMap["entries"].([]map[string]any)
		require.True(t, ok)
		assert.Len(t, entries, 0)
	})

	t.Run("directory not found", func(t *testing.T) {
		nonExistentDir := filepath.Join(testDir, "nonexistent")
		result, err := fs.ListFiles(toolCtx, ListFilesInput{Path: nonExistentDir})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeIO, result.Error.Code)
	})

	t.Run("path validation failure", func(t *testing.T) {
		unauthorizedPath := "/unauthorized/path"
		result, err := fs.ListFiles(toolCtx, ListFilesInput{Path: unauthorizedPath})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})
}

// TestFileToolset_DeleteFile tests deleteFile tool
func TestFileToolset_DeleteFile(t *testing.T) {
	t.Parallel()

	testDir := setupTestDir(t)
	pathVal, err := security.NewPath([]string{testDir})
	require.NoError(t, err)
	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful delete", func(t *testing.T) {
		testFile := filepath.Join(testDir, "to_delete.txt")
		err := os.WriteFile(testFile, []byte("content"), 0600)
		require.NoError(t, err)

		result, err := fs.DeleteFile(toolCtx, DeleteFileInput{Path: testFile})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)
		assert.Contains(t, result.Message, "Successfully deleted file")

		// Verify file was deleted
		_, err = os.Stat(testFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("file not found", func(t *testing.T) {
		nonExistentFile := filepath.Join(testDir, "nonexistent.txt")
		result, err := fs.DeleteFile(toolCtx, DeleteFileInput{Path: nonExistentFile})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeIO, result.Error.Code)
	})

	t.Run("path validation failure", func(t *testing.T) {
		unauthorizedPath := "/unauthorized/path/file.txt"
		result, err := fs.DeleteFile(toolCtx, DeleteFileInput{Path: unauthorizedPath})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})
}

// TestFileToolset_GetFileInfo tests getFileInfo tool
func TestFileToolset_GetFileInfo(t *testing.T) {
	t.Parallel()

	testDir := setupTestDir(t)
	testFile := filepath.Join(testDir, "info.txt")
	testContent := "test content"
	err := os.WriteFile(testFile, []byte(testContent), 0600)
	require.NoError(t, err)

	pathVal, err := security.NewPath([]string{testDir})
	require.NoError(t, err)
	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful get file info", func(t *testing.T) {
		result, err := fs.GetFileInfo(toolCtx, GetFileInfoInput{Path: testFile})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		// Verify file info fields
		name, ok := dataMap["name"].(string)
		require.True(t, ok)
		assert.Equal(t, "info.txt", name)

		size, ok := dataMap["size"].(int64)
		require.True(t, ok)
		assert.Equal(t, int64(len(testContent)), size)

		isDir, ok := dataMap["is_dir"].(bool)
		require.True(t, ok)
		assert.False(t, isDir)

		modified, ok := dataMap["modified"].(string)
		require.True(t, ok)
		assert.NotEmpty(t, modified)

		permissions, ok := dataMap["permissions"].(string)
		require.True(t, ok)
		assert.NotEmpty(t, permissions)
	})

	t.Run("directory info", func(t *testing.T) {
		testSubDir := filepath.Join(testDir, "subdir")
		err := os.Mkdir(testSubDir, 0750)
		require.NoError(t, err)

		result, err := fs.GetFileInfo(toolCtx, GetFileInfoInput{Path: testSubDir})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		isDir, ok := dataMap["is_dir"].(bool)
		require.True(t, ok)
		assert.True(t, isDir)
	})

	t.Run("file not found", func(t *testing.T) {
		nonExistentFile := filepath.Join(testDir, "nonexistent.txt")
		result, err := fs.GetFileInfo(toolCtx, GetFileInfoInput{Path: nonExistentFile})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeIO, result.Error.Code)
	})

	t.Run("path validation failure", func(t *testing.T) {
		unauthorizedPath := "/unauthorized/path/file.txt"
		result, err := fs.GetFileInfo(toolCtx, GetFileInfoInput{Path: unauthorizedPath})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})
}

// Helper functions

// setupTestDir creates a test directory and resolves symlinks (for macOS /var -> /private/var)
func setupTestDir(t *testing.T) string {
	t.Helper()
	testDir := t.TempDir()
	// Resolve symlinks for macOS compatibility
	realDir, err := filepath.EvalSymlinks(testDir)
	require.NoError(t, err)
	return realDir
}

// mockLogger and createTestInvocationContext are defined in testing.go

// ============================================================================
// Test Tool Metadata - IsLongRunning
// ============================================================================

func TestFileToolset_ToolMetadata_IsLongRunning(t *testing.T) {
	t.Parallel()

	pathVal, err := security.NewPath([]string{})
	require.NoError(t, err)

	fs, err := NewFileToolset(pathVal, testLogger())
	require.NoError(t, err)

	ctx := createTestInvocationContext(t)
	tools, err := fs.Tools(ctx)
	require.NoError(t, err)

	// Verify all file tools are not long running
	for _, tool := range tools {
		assert.False(t, tool.IsLongRunning(), "file tool %s should not be long running", tool.Name())
	}
}
