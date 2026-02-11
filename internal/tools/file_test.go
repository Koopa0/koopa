package tools

import (
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

func TestFile_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		pathVal, err := security.NewPath([]string{"/tmp"})
		if err != nil {
			t.Fatalf("creating path validator: %v", err)
		}

		ft, err := NewFile(pathVal, testLogger())
		if err != nil {
			t.Errorf("NewFile() error = %v, want nil", err)
		}
		if ft == nil {
			t.Error("NewFile() returned nil, want non-nil")
		}
	})

	t.Run("nil path validator", func(t *testing.T) {
		ft, err := NewFile(nil, testLogger())
		if err == nil {
			t.Error("NewFile() error = nil, want error")
		}
		if ft != nil {
			t.Error("NewFile() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		pathVal, err := security.NewPath([]string{"/tmp"})
		if err != nil {
			t.Fatalf("creating path validator: %v", err)
		}

		ft, err := NewFile(pathVal, nil)
		if err == nil {
			t.Error("NewFile() error = nil, want error")
		}
		if ft != nil {
			t.Error("NewFile() returned non-nil, want nil")
		}
	})
}

func TestFileToolConstants(t *testing.T) {
	// Verify tool name constants are correct
	expectedNames := map[string]string{
		"ReadFileName":   "read_file",
		"WriteFileName":  "write_file",
		"ListFilesName":  "list_files",
		"DeleteFileName": "delete_file",
		"FileInfoName":   "get_file_info",
	}

	if ReadFileName != expectedNames["ReadFileName"] {
		t.Errorf("ReadFileName = %q, want %q", ReadFileName, expectedNames["ReadFileName"])
	}
	if WriteFileName != expectedNames["WriteFileName"] {
		t.Errorf("WriteFileName = %q, want %q", WriteFileName, expectedNames["WriteFileName"])
	}
	if ListFilesName != expectedNames["ListFilesName"] {
		t.Errorf("ListFilesName = %q, want %q", ListFilesName, expectedNames["ListFilesName"])
	}
	if DeleteFileName != expectedNames["DeleteFileName"] {
		t.Errorf("DeleteFileName = %q, want %q", DeleteFileName, expectedNames["DeleteFileName"])
	}
	if FileInfoName != expectedNames["FileInfoName"] {
		t.Errorf("FileInfoName = %q, want %q", FileInfoName, expectedNames["FileInfoName"])
	}
}

func TestMaxReadFileSize(t *testing.T) {
	// Verify MaxReadFileSize is 10MB
	expected := int64(10 * 1024 * 1024)
	if MaxReadFileSize != expected {
		t.Errorf("MaxReadFileSize = %d, want %d (10MB)", MaxReadFileSize, expected)
	}
}
