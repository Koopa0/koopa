package tools

import (
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

func TestFileTools_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		pathVal, err := security.NewPath([]string{"/tmp"})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		ft, err := NewFileTools(pathVal, testLogger())
		if err != nil {
			t.Errorf("NewFileTools() error = %v, want nil", err)
		}
		if ft == nil {
			t.Error("NewFileTools() returned nil, want non-nil")
		}
	})

	t.Run("nil path validator", func(t *testing.T) {
		ft, err := NewFileTools(nil, testLogger())
		if err == nil {
			t.Error("NewFileTools() error = nil, want error")
		}
		if ft != nil {
			t.Error("NewFileTools() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		pathVal, err := security.NewPath([]string{"/tmp"})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		ft, err := NewFileTools(pathVal, nil)
		if err == nil {
			t.Error("NewFileTools() error = nil, want error")
		}
		if ft != nil {
			t.Error("NewFileTools() returned non-nil, want nil")
		}
	})
}

func TestFileToolConstants(t *testing.T) {
	// Verify tool name constants are correct
	expectedNames := map[string]string{
		"ToolReadFile":    "read_file",
		"ToolWriteFile":   "write_file",
		"ToolListFiles":   "list_files",
		"ToolDeleteFile":  "delete_file",
		"ToolGetFileInfo": "get_file_info",
	}

	if ToolReadFile != expectedNames["ToolReadFile"] {
		t.Errorf("ToolReadFile = %q, want %q", ToolReadFile, expectedNames["ToolReadFile"])
	}
	if ToolWriteFile != expectedNames["ToolWriteFile"] {
		t.Errorf("ToolWriteFile = %q, want %q", ToolWriteFile, expectedNames["ToolWriteFile"])
	}
	if ToolListFiles != expectedNames["ToolListFiles"] {
		t.Errorf("ToolListFiles = %q, want %q", ToolListFiles, expectedNames["ToolListFiles"])
	}
	if ToolDeleteFile != expectedNames["ToolDeleteFile"] {
		t.Errorf("ToolDeleteFile = %q, want %q", ToolDeleteFile, expectedNames["ToolDeleteFile"])
	}
	if ToolGetFileInfo != expectedNames["ToolGetFileInfo"] {
		t.Errorf("ToolGetFileInfo = %q, want %q", ToolGetFileInfo, expectedNames["ToolGetFileInfo"])
	}
}

func TestMaxReadFileSize(t *testing.T) {
	// Verify MaxReadFileSize is 10MB
	expected := int64(10 * 1024 * 1024)
	if MaxReadFileSize != expected {
		t.Errorf("MaxReadFileSize = %d, want %d (10MB)", MaxReadFileSize, expected)
	}
}

func TestReadFileInput(t *testing.T) {
	// Test that ReadFileInput struct can be created
	input := ReadFileInput{Path: "/tmp/test.txt"}
	if input.Path != "/tmp/test.txt" {
		t.Errorf("ReadFileInput.Path = %q, want %q", input.Path, "/tmp/test.txt")
	}
}

func TestWriteFileInput(t *testing.T) {
	input := WriteFileInput{
		Path:    "/tmp/test.txt",
		Content: "hello world",
	}
	if input.Path != "/tmp/test.txt" {
		t.Errorf("WriteFileInput.Path = %q, want %q", input.Path, "/tmp/test.txt")
	}
	if input.Content != "hello world" {
		t.Errorf("WriteFileInput.Content = %q, want %q", input.Content, "hello world")
	}
}

func TestListFilesInput(t *testing.T) {
	input := ListFilesInput{Path: "/tmp"}
	if input.Path != "/tmp" {
		t.Errorf("ListFilesInput.Path = %q, want %q", input.Path, "/tmp")
	}
}

func TestDeleteFileInput(t *testing.T) {
	input := DeleteFileInput{Path: "/tmp/test.txt"}
	if input.Path != "/tmp/test.txt" {
		t.Errorf("DeleteFileInput.Path = %q, want %q", input.Path, "/tmp/test.txt")
	}
}

func TestGetFileInfoInput(t *testing.T) {
	input := GetFileInfoInput{Path: "/tmp/test.txt"}
	if input.Path != "/tmp/test.txt" {
		t.Errorf("GetFileInfoInput.Path = %q, want %q", input.Path, "/tmp/test.txt")
	}
}
