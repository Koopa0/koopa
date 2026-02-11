package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGetStateFilePath(t *testing.T) {
	// Note: Testing private function getStateFilePath (accessible within same package)
	// Use isolated temp directory for this test
	tempDir := t.TempDir()
	t.Setenv("KOOPA_STATE_DIR", tempDir)

	path, err := getStateFilePath()
	if err != nil {
		t.Fatalf("getStateFilePath() error = %v", err)
	}

	if path == "" {
		t.Error("getStateFilePath() returned empty path")
	}

	// Verify path is absolute
	if !filepath.IsAbs(path) {
		t.Errorf("getStateFilePath() returned relative path: %q", path)
	}

	// Verify path uses temp directory
	rel, err := filepath.Rel(tempDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("getStateFilePath() = %q, want within %q", path, tempDir)
	}

	// Verify directory was created
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("getStateFilePath() did not create directory: %q", dir)
	}
}

func TestSaveAndLoadCurrentSessionID(t *testing.T) {
	// Use isolated temp directory for all sub-tests
	tempDir := t.TempDir()
	t.Setenv("KOOPA_STATE_DIR", tempDir)

	t.Run("save and load session ID", func(t *testing.T) {
		testID := uuid.New()

		// Save session ID
		err := SaveCurrentSessionID(testID)
		if err != nil {
			t.Fatalf("SaveCurrentSessionID() error = %v", err)
		}

		// Load session ID
		loadedID, err := LoadCurrentSessionID()
		if err != nil {
			t.Fatalf("LoadCurrentSessionID() error = %v", err)
		}

		if loadedID == nil {
			t.Fatal("LoadCurrentSessionID() returned nil")
		}

		if *loadedID != testID {
			t.Errorf("LoadCurrentSessionID() = %v, want %v", *loadedID, testID)
		}
	})

	t.Run("load returns nil when file doesn't exist", func(t *testing.T) {
		// Ensure file doesn't exist
		_ = ClearCurrentSessionID()

		loadedID, err := LoadCurrentSessionID()
		if err != nil {
			t.Errorf("LoadCurrentSessionID() error = %v, want nil", err)
		}

		if loadedID != nil {
			t.Errorf("LoadCurrentSessionID() = %v, want nil", *loadedID)
		}
	})

	t.Run("overwrite existing session ID", func(t *testing.T) {
		firstID := uuid.New()
		secondID := uuid.New()

		// Save first ID
		err := SaveCurrentSessionID(firstID)
		if err != nil {
			t.Fatalf("SaveCurrentSessionID() first save error = %v", err)
		}

		// Overwrite with second ID
		err = SaveCurrentSessionID(secondID)
		if err != nil {
			t.Fatalf("SaveCurrentSessionID() second save error = %v", err)
		}

		// Load and verify second ID
		loadedID, err := LoadCurrentSessionID()
		if err != nil {
			t.Fatalf("LoadCurrentSessionID() error = %v", err)
		}

		if loadedID == nil {
			t.Fatal("LoadCurrentSessionID() returned nil")
		}

		if *loadedID != secondID {
			t.Errorf("LoadCurrentSessionID() = %v, want %v", *loadedID, secondID)
		}
	})
}

func TestClearCurrentSessionID(t *testing.T) {
	// Use isolated temp directory for all sub-tests
	tempDir := t.TempDir()
	t.Setenv("KOOPA_STATE_DIR", tempDir)

	t.Run("clear existing session ID", func(t *testing.T) {
		// Set up - save a session ID first
		testID := uuid.New()
		err := SaveCurrentSessionID(testID)
		if err != nil {
			t.Fatalf("SaveCurrentSessionID() setup error = %v", err)
		}

		// Clear session ID
		err = ClearCurrentSessionID()
		if err != nil {
			t.Errorf("ClearCurrentSessionID() error = %v", err)
		}

		// Verify file was deleted
		loadedID, err := LoadCurrentSessionID()
		if err != nil {
			t.Errorf("LoadCurrentSessionID() error = %v", err)
		}

		if loadedID != nil {
			t.Errorf("LoadCurrentSessionID() after clear = %v, want nil", *loadedID)
		}
	})

	t.Run("clear when file doesn't exist is not an error", func(t *testing.T) {
		// Ensure file doesn't exist
		_ = ClearCurrentSessionID()

		// Clear again should not error
		err := ClearCurrentSessionID()
		if err != nil {
			t.Errorf("ClearCurrentSessionID() on non-existent file error = %v, want nil", err)
		}
	})
}

func TestLoadCurrentSessionID_InvalidContent(t *testing.T) {
	// Use isolated temp directory for all sub-tests
	tempDir := t.TempDir()
	t.Setenv("KOOPA_STATE_DIR", tempDir)

	tests := []struct {
		name    string
		content string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "empty file returns nil",
			content: "",
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "whitespace only returns nil",
			content: "   \n\t  ",
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "invalid UUID returns error",
			content: "not-a-valid-uuid",
			wantErr: true,
		},
		{
			name:    "malformed UUID returns error",
			content: "12345678-1234-1234-1234",
			wantErr: true,
		},
		{
			name:    "valid UUID returns success",
			content: "550e8400-e29b-41d4-a716-446655440000",
			wantNil: false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test content directly to state file
			filePath, err := getStateFilePath()
			if err != nil {
				t.Fatalf("getStateFilePath() error = %v", err)
			}

			err = os.WriteFile(filePath, []byte(tt.content), 0o600)
			if err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			// Try to load
			loadedID, err := LoadCurrentSessionID()

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadCurrentSessionID() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantNil && loadedID != nil {
				t.Errorf("LoadCurrentSessionID() = %v, want nil", *loadedID)
			}

			if !tt.wantNil && !tt.wantErr && loadedID == nil {
				t.Error("LoadCurrentSessionID() returned nil, want non-nil")
			}
		})
	}
}
