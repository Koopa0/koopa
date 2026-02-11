package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestReadFile_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Create test file
	testFile := filepath.Join(h.tempDir, "test.txt")
	testContent := "hello world"
	if err := os.WriteFile(testFile, []byte(testContent), 0o600); err != nil {
		t.Fatalf("creating test file: %v", err)
	}

	// Call ReadFile handler
	result, _, err := server.ReadFile(context.Background(), &mcp.CallToolRequest{}, tools.ReadFileInput{
		Path: testFile,
	})

	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}

	if result.IsError {
		t.Errorf("ReadFile returned error: %v", result.Content)
	}

	// Check result contains success message
	if len(result.Content) == 0 {
		t.Fatal("ReadFile returned empty content")
	}
}

func TestReadFile_FileNotFound(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Call ReadFile with non-existent file
	result, _, err := server.ReadFile(context.Background(), &mcp.CallToolRequest{}, tools.ReadFileInput{
		Path: filepath.Join(h.tempDir, "nonexistent.txt"),
	})

	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	if !result.IsError {
		t.Error("ReadFile should return IsError=true for non-existent file")
	}
}

func TestReadFile_SecurityViolation(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Try to read file outside allowed directory
	result, _, err := server.ReadFile(context.Background(), &mcp.CallToolRequest{}, tools.ReadFileInput{
		Path: "/etc/passwd",
	})

	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	if !result.IsError {
		t.Error("ReadFile should return IsError=true for path outside allowed directory")
	}
}

func TestWriteFile_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	testFile := filepath.Join(h.tempDir, "write_test.txt")
	testContent := "written content"

	result, _, err := server.WriteFile(context.Background(), &mcp.CallToolRequest{}, tools.WriteFileInput{
		Path:    testFile,
		Content: testContent,
	})

	if err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	if result.IsError {
		t.Errorf("WriteFile returned error: %v", result.Content)
	}

	// Verify file was created
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("file content = %q, want %q", string(content), testContent)
	}
}

func TestWriteFile_CreatesDirectory(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Write to a file in a non-existent subdirectory
	testFile := filepath.Join(h.tempDir, "subdir", "nested", "test.txt")

	result, _, err := server.WriteFile(context.Background(), &mcp.CallToolRequest{}, tools.WriteFileInput{
		Path:    testFile,
		Content: "nested content",
	})

	if err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	if result.IsError {
		t.Errorf("WriteFile returned error: %v", result.Content)
	}

	// Verify directory was created
	if _, err := os.Stat(filepath.Dir(testFile)); os.IsNotExist(err) {
		t.Error("WriteFile did not create parent directories")
	}
}

func TestListFiles_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Create some test files
	for _, name := range []string{"file1.txt", "file2.txt"} {
		if err := os.WriteFile(filepath.Join(h.tempDir, name), []byte("test"), 0o600); err != nil {
			t.Fatalf("creating test file: %v", err)
		}
	}

	// Create a subdirectory
	if err := os.Mkdir(filepath.Join(h.tempDir, "subdir"), 0o750); err != nil {
		t.Fatalf("creating subdirectory: %v", err)
	}

	result, _, err := server.ListFiles(context.Background(), &mcp.CallToolRequest{}, tools.ListFilesInput{
		Path: h.tempDir,
	})

	if err != nil {
		t.Fatalf("ListFiles(): %v", err)
	}

	if result.IsError {
		t.Errorf("ListFiles returned error: %v", result.Content)
	}
}

func TestListFiles_DirectoryNotFound(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	result, _, err := server.ListFiles(context.Background(), &mcp.CallToolRequest{}, tools.ListFilesInput{
		Path: filepath.Join(h.tempDir, "nonexistent"),
	})

	if err != nil {
		t.Fatalf("ListFiles returned error: %v", err)
	}

	if !result.IsError {
		t.Error("ListFiles should return IsError=true for non-existent directory")
	}
}

func TestDeleteFile_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Create test file
	testFile := filepath.Join(h.tempDir, "to_delete.txt")
	if err := os.WriteFile(testFile, []byte("delete me"), 0o600); err != nil {
		t.Fatalf("creating test file: %v", err)
	}

	result, _, err := server.DeleteFile(context.Background(), &mcp.CallToolRequest{}, tools.DeleteFileInput{
		Path: testFile,
	})

	if err != nil {
		t.Fatalf("DeleteFile(): %v", err)
	}

	if result.IsError {
		t.Errorf("DeleteFile returned error: %v", result.Content)
	}

	// Verify file was deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("DeleteFile did not delete the file")
	}
}

func TestDeleteFile_FileNotFound(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	result, _, err := server.DeleteFile(context.Background(), &mcp.CallToolRequest{}, tools.DeleteFileInput{
		Path: filepath.Join(h.tempDir, "nonexistent.txt"),
	})

	if err != nil {
		t.Fatalf("DeleteFile returned error: %v", err)
	}

	if !result.IsError {
		t.Error("DeleteFile should return IsError=true for non-existent file")
	}
}

func TestGetFileInfo_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	// Create test file
	testFile := filepath.Join(h.tempDir, "info_test.txt")
	testContent := "test content for info"
	if err := os.WriteFile(testFile, []byte(testContent), 0o600); err != nil {
		t.Fatalf("creating test file: %v", err)
	}

	result, _, err := server.GetFileInfo(context.Background(), &mcp.CallToolRequest{}, tools.GetFileInfoInput{
		Path: testFile,
	})

	if err != nil {
		t.Fatalf("GetFileInfo(): %v", err)
	}

	if result.IsError {
		t.Errorf("GetFileInfo returned error: %v", result.Content)
	}
}

func TestGetFileInfo_FileNotFound(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	result, _, err := server.GetFileInfo(context.Background(), &mcp.CallToolRequest{}, tools.GetFileInfoInput{
		Path: filepath.Join(h.tempDir, "nonexistent.txt"),
	})

	if err != nil {
		t.Fatalf("GetFileInfo returned error: %v", err)
	}

	if !result.IsError {
		t.Error("GetFileInfo should return IsError=true for non-existent file")
	}
}
