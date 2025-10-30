package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// registerFileTools registers filesystem-related tools
// pathValidator is passed as parameter and captured by closures (Go best practice)
func registerFileTools(g *genkit.Genkit, pathValidator *security.PathValidator) {
	// 1. Read file
	genkit.DefineTool(
		g, "readFile", "Read file content",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File path to read"`
		},
		) (string, error) {
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			content, err := os.ReadFile(safePath) // #nosec G304 -- path validated by pathValidator above
			if err != nil {
				return "", fmt.Errorf("unable to read file: %w", err)
			}
			return string(content), nil
		},
	)

	// 2. Write file
	genkit.DefineTool(
		g, "writeFile", "Write content to file",
		func(ctx *ai.ToolContext, input struct {
			Path    string `json:"path" jsonschema_description:"File path to write to"`
			Content string `json:"content" jsonschema_description:"Content to write"`
		},
		) (string, error) {
			// Path security validation (prevent path traversal attacks CWE-22)
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			// Ensure directory exists (use 0750 permission for better security)
			dir := filepath.Dir(safePath)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return "", fmt.Errorf("unable to create directory: %w", err)
			}

			if err = os.WriteFile(safePath, []byte(input.Content), 0o600); err != nil {
				return "", fmt.Errorf("unable to write file: %w", err)
			}
			return fmt.Sprintf("Successfully wrote file: %s", safePath), nil
		},
	)

	// 3. List directory contents
	genkit.DefineTool(
		g, "listFiles", "List files and subdirectories in a directory",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"Directory path to list"`
		},
		) (string, error) {
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			entries, err := os.ReadDir(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to read directory: %w", err)
			}

			var result []string
			for _, entry := range entries {
				prefix := "[File]"
				if entry.IsDir() {
					prefix = "[Directory]"
				}
				result = append(result, fmt.Sprintf("%s %s", prefix, entry.Name()))
			}

			return strings.Join(result, "\n"), nil
		},
	)

	// 4. Delete file
	genkit.DefineTool(
		g, "deleteFile", "Delete specified file",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File path to delete"`
		},
		) (string, error) {
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			if err = os.Remove(safePath); err != nil {
				return "", fmt.Errorf("unable to delete file: %w", err)
			}
			return fmt.Sprintf("Successfully deleted file: %s", safePath), nil
		},
	)

	// 5. Get file information
	genkit.DefineTool(
		g, "getFileInfo", "Get detailed information about a file or directory",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"File or directory path"`
		},
		) (string, error) {
			// Path security validation
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("path validation failed: %w", err)
			}

			info, err := os.Stat(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to get file information: %w", err)
			}

			result := fmt.Sprintf("Name: %s\n", info.Name())
			result += fmt.Sprintf("Size: %d bytes\n", info.Size())
			result += fmt.Sprintf("Is directory: %v\n", info.IsDir())
			result += fmt.Sprintf("Modified time: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
			result += fmt.Sprintf("Permissions: %s\n", info.Mode().String())

			return result, nil
		},
	)
}
