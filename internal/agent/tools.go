package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// cmdValidator command validator (uses unified security module)
var cmdValidator = security.NewCommandValidator()

// httpValidator HTTP request validator (prevents SSRF attacks)
var httpValidator = security.NewHTTPValidator()

// envValidator environment variable validator (prevents sensitive information leakage)
var envValidator = security.NewEnvValidator()

// registerTools registers all available tools
func registerTools(g *genkit.Genkit) {
	// 1. Get current time
	genkit.DefineTool(
		g, "currentTime", "Get current time",
		func(ctx *ai.ToolContext, input struct{}) (string, error) {
			now := time.Now()
			return now.Format("2006-01-02 15:04:05 (Monday)"), nil
		},
	)

	// 2. Read file
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

			content, err := os.ReadFile(safePath)
			if err != nil {
				return "", fmt.Errorf("unable to read file: %w", err)
			}
			return string(content), nil
		},
	)

	// 3. Write file
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

	// 4. List directory contents
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

	// 5. Delete file
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

	// 6. Execute system command
	genkit.DefineTool(
		g, "executeCommand", "Execute system command (use with caution, dangerous commands are automatically checked)",
		func(ctx *ai.ToolContext, input struct {
			Command string   `json:"command" jsonschema_description:"Command to execute"`
			Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments (optional)"`
		},
		) (string, error) {
			// Command security validation (prevent command injection attacks CWE-78)
			if err := cmdValidator.ValidateCommand(input.Command, input.Args); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: Dangerous command rejected\nCommand: %s %s\nReason: %w\nIf you need to execute this, please run it manually in the terminal",
					input.Command, strings.Join(input.Args, " "), err)
			}

			cmd := exec.Command(input.Command, input.Args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("command execution failed: %w\nOutput: %s", err, string(output))
			}
			return string(output), nil
		},
	)

	// 7. HTTP GET request (with SSRF protection)
	genkit.DefineTool(
		g, "httpGet", "Send HTTP GET request (SSRF protection enabled)",
		func(ctx *ai.ToolContext, input struct {
			URL string `json:"url" jsonschema_description:"URL to request"`
		},
		) (string, error) {
			// URL security validation (prevent SSRF attacks)
			if err := httpValidator.ValidateURL(input.URL); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: URL validation failed\nReason: %w\nThis may be an attempt to access internal network or metadata services", err)
			}

			// Use securely configured HTTP client (with timeout and redirect limits)
			client := httpValidator.CreateSafeHTTPClient()
			resp, err := client.Get(input.URL)
			if err != nil {
				return "", fmt.Errorf("HTTP request failed: %w", err)
			}
			defer resp.Body.Close()

			// Limit response size (prevent resource exhaustion)
			maxSize := httpValidator.GetMaxResponseSize()
			limitedReader := io.LimitReader(resp.Body, maxSize)

			body, err := io.ReadAll(limitedReader)
			if err != nil {
				return "", fmt.Errorf("failed to read response: %w", err)
			}

			// Check if size limit exceeded
			if int64(len(body)) >= maxSize {
				return "", fmt.Errorf("response size exceeds limit (max %d MB)", maxSize/(1024*1024))
			}

			result := map[string]any{
				"status": resp.StatusCode,
				"body":   string(body),
			}

			jsonResult, _ := json.Marshal(result)
			return string(jsonResult), nil
		},
	)

	// 8. Read environment variable (restricted access)
	genkit.DefineTool(
		g, "getEnv", "Read environment variable (sensitive variables are protected)",
		func(ctx *ai.ToolContext, input struct {
			Name string `json:"name" jsonschema_description:"Environment variable name"`
		},
		) (string, error) {
			// Environment variable security validation (prevent sensitive information leakage)
			if err := envValidator.ValidateEnvAccess(input.Name); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: %w\nNote: This environment variable may contain sensitive information and is protected.\nIf you need to access it, please check it directly in the terminal", err)
			}

			value := os.Getenv(input.Name)
			if value == "" {
				return fmt.Sprintf("Environment variable %s is not set or is empty", input.Name), nil
			}
			return value, nil
		},
	)

	// 9. Get file information
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
