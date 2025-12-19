package artifact

import "errors"

var (
	// ErrNotFound is returned when the requested artifact does not exist.
	ErrNotFound = errors.New("artifact not found")

	// ErrInvalidFilename is returned when the filename contains invalid characters
	// or fails security validation.
	ErrInvalidFilename = errors.New("invalid filename")
)

// ValidateFilename checks if the filename is safe for use.
// Returns ErrInvalidFilename if validation fails.
//
// Validation rules:
//   - Must not be empty
//   - Must not exceed 255 characters
//   - Must not contain path separators (/, \)
//   - Must not contain null bytes
//   - Must not be "." or ".." (path traversal)
func ValidateFilename(name string) error {
	if name == "" {
		return ErrInvalidFilename
	}
	if len(name) > 255 {
		return ErrInvalidFilename
	}
	// Prevent path traversal
	for _, c := range name {
		if c == '/' || c == '\\' || c == '\x00' {
			return ErrInvalidFilename
		}
	}
	if name == "." || name == ".." {
		return ErrInvalidFilename
	}
	return nil
}
