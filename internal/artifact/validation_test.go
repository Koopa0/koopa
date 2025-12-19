package artifact

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		// Valid cases
		{"valid simple", "main.go", false},
		{"valid with dots", "file.test.go", false},
		{"valid with underscore", "my_file.txt", false},
		{"valid with dash", "my-file.txt", false},
		{"valid with spaces", "my file.txt", false},
		{"valid unicode", "文件.txt", false},

		// Invalid cases
		{"empty", "", true},
		{"path traversal dot", ".", true},
		{"path traversal dotdot", "..", true},
		{"forward slash", "path/to/file.txt", true},
		{"backslash", "path\\to\\file.txt", true},
		{"null byte", "file\x00.txt", true},
		{"too long", strings.Repeat("a", 256), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateFilename(tt.filename)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidFilename)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFilename_MaxLength(t *testing.T) {
	t.Parallel()

	// Create a string of 255 'a' characters (valid)
	valid255 := make([]byte, 255)
	for i := range valid255 {
		valid255[i] = 'a'
	}
	assert.NoError(t, ValidateFilename(string(valid255)))

	// Create a string of 256 'a' characters (invalid - too long)
	invalid256 := make([]byte, 256)
	for i := range invalid256 {
		invalid256[i] = 'a'
	}
	assert.ErrorIs(t, ValidateFilename(string(invalid256)), ErrInvalidFilename)
}

func FuzzValidateFilename(f *testing.F) {
	// Seed corpus
	f.Add("main.go")
	f.Add("../../../etc/passwd")
	f.Add("file\x00.exe")
	f.Add("/etc/passwd")
	f.Add("C:\\Windows\\System32")
	f.Add(".")
	f.Add("..")
	f.Add("")
	f.Add(strings.Repeat("a", 300))

	f.Fuzz(func(t *testing.T, filename string) {
		// Should never panic
		err := ValidateFilename(filename)

		// If valid, verify security properties
		if err == nil {
			// Must not be empty
			if filename == "" {
				t.Error("empty filename should be invalid")
			}
			// Must not contain path separators
			for _, c := range filename {
				if c == '/' || c == '\\' || c == '\x00' {
					t.Errorf("filename with path separator should be invalid: %q", filename)
				}
			}
			// Must not be path traversal
			if filename == "." || filename == ".." {
				t.Error("path traversal should be invalid")
			}
			// Must not exceed length
			if len(filename) > 255 {
				t.Error("filename exceeding 255 chars should be invalid")
			}
		}
	})
}
