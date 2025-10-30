package flows

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// readFileWithLimit reads file content with size limit
// maxBytes: maximum bytes, 0 means unlimited
// For log files: returns last N bytes (tail)
// For regular files: returns first N bytes (head)
// pathValidator is passed as parameter (Go best practice, no package-level state)
func readFileWithLimit(ctx context.Context, pathValidator *security.PathValidator, filePath string, maxBytes int) (string, error) {
	return genkit.Run(ctx, "read-file",
		func() (string, error) {
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(filePath)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			data, err := os.ReadFile(safePath) // #nosec G304 -- path validated by pathValidator above
			if err != nil {
				return "", fmt.Errorf("unable to read file %s: %w", safePath, err)
			}

			// Unlimited
			if maxBytes <= 0 || len(data) <= maxBytes {
				return string(data), nil
			}

			// Determine if this is a log file
			// Log files take tail (latest content), regular files take head
			fileName := strings.ToLower(filepath.Base(filePath))
			isLogFile := strings.HasSuffix(fileName, ".log") ||
				strings.Contains(fileName, ".log.") ||
				strings.HasPrefix(fileName, "log")

			if isLogFile {
				// Take last maxBytes bytes
				return string(data[len(data)-maxBytes:]), nil
			}
			// Regular files take first maxBytes bytes
			return string(data[:maxBytes]) + "...", nil
		})
}
