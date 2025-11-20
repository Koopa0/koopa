// Package tools provides Genkit tool registration and management.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
)

// HTTPValidator defines the interface for HTTP security validation.
// Following Go best practices: interfaces are defined by the consumer,
// not the provider (similar to http.RoundTripper, sql.Driver).
//
// This interface allows Handler to depend on abstraction rather than
// concrete implementation, improving testability and flexibility.
type HTTPValidator interface {
	// ValidateURL validates a URL to prevent SSRF attacks
	ValidateURL(url string) error

	// Client returns a configured HTTP client
	Client() *http.Client

	// MaxResponseSize returns the maximum allowed response size in bytes
	MaxResponseSize() int64
}

// KnowledgeSearcher defines the interface for knowledge search operations.
// Following Go best practices: interfaces are defined by the consumer,
// not the provider (similar to http.RoundTripper, sql.Driver).
//
// This interface allows Handler to depend on abstraction rather than
// concrete implementation, improving testability and flexibility.
type KnowledgeSearcher interface {
	// Search performs semantic search on knowledge documents
	Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error)
}

// Handler manages tool operations with security validation.
// Follows Go naming conventions (like http.Server, mcp.Server, sql.DB).
//
// This type encapsulates all tool logic with proper dependency injection,
// making methods independently testable without Genkit's closure overhead.
//
// Design: Handler depends on interfaces (HTTPValidator, KnowledgeSearcher) rather
// than concrete types where testability is critical, following the "Accept interfaces,
// return structs" principle.
type Handler struct {
	pathVal        *security.Path
	cmdVal         *security.Command
	httpVal        HTTPValidator // Depends on interface for testability
	envVal         *security.Env
	knowledgeStore KnowledgeSearcher // Depends on interface for testability
}

// NewHandler creates a new tool handler with security validators.
//
// Parameters:
//   - pathVal: Path validator for file operations (prevents CWE-22 path traversal)
//   - cmdVal: Command validator for system operations (prevents CWE-78 command injection)
//   - httpVal: HTTP validator for network operations (prevents SSRF)
//   - envVal: Environment validator (prevents sensitive information leakage)
//   - knowledgeStore: Knowledge searcher for semantic search operations
//
// Returns:
//   - *Handler: Handler instance ready to process tool operations
//
// Design: Accepts HTTPValidator and KnowledgeSearcher interfaces following
// "Accept interfaces, return structs" principle for better testability.
func NewHandler(
	pathVal *security.Path,
	cmdVal *security.Command,
	httpVal HTTPValidator,
	envVal *security.Env,
	knowledgeStore KnowledgeSearcher,
) *Handler {
	return &Handler{
		pathVal:        pathVal,
		cmdVal:         cmdVal,
		httpVal:        httpVal,
		envVal:         envVal,
		knowledgeStore: knowledgeStore,
	}
}

// File Operations

// ReadFile reads and returns the content of a file.
// The path is validated before access to prevent path traversal attacks (CWE-22).
//
// Parameters:
//   - path: File path to read (absolute or relative)
//
// Returns:
//   - string: File content
//   - error: If validation fails or file cannot be read
func (h *Handler) ReadFile(path string) (string, error) {
	safePath, err := h.pathVal.Validate(path)
	if err != nil {
		return "", fmt.Errorf("path validation failed: %w", err)
	}

	content, err := os.ReadFile(safePath) // #nosec G304 -- path validated by pathVal above
	if err != nil {
		return "", fmt.Errorf("unable to read file: %w", err)
	}

	return string(content), nil
}

// WriteFile writes content to a file with secure permissions (0600).
// Creates parent directories if needed (0750). Overwrites existing files.
//
// Parameters:
//   - path: File path to write (absolute or relative)
//   - content: Content to write
//
// Returns:
//   - string: Success message with file path
//   - error: If validation fails or file cannot be written
func (h *Handler) WriteFile(path, content string) (string, error) {
	safePath, err := h.pathVal.Validate(path)
	if err != nil {
		return "", fmt.Errorf("path validation failed: %w", err)
	}

	// Ensure directory exists (use 0750 permission for better security)
	dir := filepath.Dir(safePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("unable to create directory: %w", err)
	}

	if err := os.WriteFile(safePath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("unable to write file: %w", err)
	}

	return fmt.Sprintf("successfully wrote file: %s", safePath), nil
}

// ListFiles lists all files and subdirectories in a directory.
// Returns a formatted list with [File] and [Directory] prefixes.
//
// Parameters:
//   - path: Directory path to list (absolute or relative)
//
// Returns:
//   - string: Formatted list of directory entries (one per line)
//   - error: If validation fails or directory cannot be read
func (h *Handler) ListFiles(path string) (string, error) {
	safePath, err := h.pathVal.Validate(path)
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
}

// DeleteFile permanently deletes a file from the filesystem.
// WARNING: This action is irreversible!
//
// Parameters:
//   - path: File path to delete (absolute or relative)
//
// Returns:
//   - string: Success message with file path
//   - error: If validation fails or file cannot be deleted
func (h *Handler) DeleteFile(path string) (string, error) {
	safePath, err := h.pathVal.Validate(path)
	if err != nil {
		return "", fmt.Errorf("path validation failed: %w", err)
	}

	if err := os.Remove(safePath); err != nil {
		return "", fmt.Errorf("unable to delete file: %w", err)
	}

	return fmt.Sprintf("successfully deleted file: %s", safePath), nil
}

// GetFileInfo returns detailed metadata about a file or directory.
// Returns name, size, type (file/directory), modification time, and permissions.
//
// Parameters:
//   - path: File or directory path to inspect (absolute or relative)
//
// Returns:
//   - string: Formatted file information
//   - error: If validation fails or file info cannot be retrieved
func (h *Handler) GetFileInfo(path string) (string, error) {
	safePath, err := h.pathVal.Validate(path)
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
}

// System Operations

// CurrentTime returns the current system date and time.
// Format: "2006-01-02 15:04:05 (Monday)"
//
// Returns:
//   - string: Formatted current timestamp with day of week
//   - error: Never returns error (included for consistency)
func (h *Handler) CurrentTime() (string, error) {
	now := time.Now()
	return now.Format("2006-01-02 15:04:05 (Monday)"), nil
}

// ExecuteCommand executes a system shell command with security validation.
// Dangerous commands (rm -rf, dd, format, sudo su, etc.) are automatically blocked.
//
// Parameters:
//   - ctx: Context for cancellation support (allows interrupting long-running commands)
//   - command: Command to execute (e.g., "ls", "git", "go")
//   - args: Command arguments as separate array elements
//
// Returns:
//   - string: Combined stdout and stderr output
//   - error: If validation fails, command execution fails, or context is cancelled
func (h *Handler) ExecuteCommand(ctx context.Context, command string, args []string) (string, error) {
	// Command security validation (prevent command injection attacks CWE-78)
	if err := h.cmdVal.ValidateCommand(command, args); err != nil {
		return "", fmt.Errorf("security warning: dangerous command rejected (%s %s): %w",
			command, strings.Join(args, " "), err)
	}

	// Use CommandContext for cancellation support (allows interrupting long-running commands)
	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 -- validated by cmdVal above
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it was cancelled by context
		if ctx.Err() != nil {
			return "", fmt.Errorf("command execution cancelled: %w", ctx.Err())
		}
		return "", fmt.Errorf("command execution failed: %w (output: %s)", err, string(output))
	}

	return string(output), nil
}

// GetEnv reads an environment variable value with security protection.
// Sensitive variables (API keys, passwords, tokens) are automatically blocked.
//
// Parameters:
//   - name: Environment variable name (e.g., "PATH", "HOME", "SHELL")
//
// Returns:
//   - string: Environment variable value or message if not set
//   - error: If validation fails (sensitive variable blocked)
func (h *Handler) GetEnv(name string) (string, error) {
	// Environment variable security validation (prevent sensitive information leakage)
	if err := h.envVal.ValidateEnvAccess(name); err != nil {
		return "", fmt.Errorf("security warning: %w (protected environment variable)", err)
	}

	value := os.Getenv(name)
	if value == "" {
		return fmt.Sprintf("environment variable %s is not set or is empty", name), nil
	}

	return value, nil
}

// Network Operations

// HTTPGet sends an HTTP GET request with comprehensive security protection.
// Security features: SSRF protection, response size limits, timeout protection.
//
// Parameters:
//   - url: Full URL to request (must start with http:// or https://)
//
// Returns:
//   - string: JSON string with "status" (int) and "body" (string) fields
//   - error: If validation fails or request fails
func (h *Handler) HTTPGet(url string) (string, error) {
	// URL security validation (prevent SSRF attacks)
	if err := h.httpVal.ValidateURL(url); err != nil {
		return "", fmt.Errorf("security warning: url validation failed (possible SSRF attempt): %w", err)
	}

	// Use reusable HTTP client (with connection pooling and security config)
	client := h.httpVal.Client()
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Limit response size (prevent resource exhaustion)
	maxSize := h.httpVal.MaxResponseSize()
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
}

// Knowledge Operations

// SearchHistory searches conversation history using semantic similarity.
// Searches only conversations (source_type="conversation").
// Returns formatted results with similarity scores and metadata.
//
// Parameters:
//   - ctx: Tool execution context
//   - query: Search query string
//   - topK: Maximum results to return (1-10, default: 3)
//
// Returns:
//   - string: Formatted search results
//   - error: If search fails
func (h *Handler) SearchHistory(ctx *ai.ToolContext, query string, topK int32) (string, error) {
	// No nil check needed - RegisterTools guarantees non-nil knowledgeStore

	// Validate and set defaults for topK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with conversation filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", "conversation"),
	}

	// Execute search
	results, err := h.knowledgeStore.Search(ctx.Context, query, opts...)
	if err != nil {
		return "", fmt.Errorf("history search failed: %w", err)
	}

	return formatHistoryResults(results), nil
}

// SearchDocuments searches indexed documents using semantic similarity.
// Searches only documents (source_type="file").
// Returns formatted results with similarity scores and metadata.
//
// Parameters:
//   - ctx: Tool execution context
//   - query: Search query string
//   - topK: Maximum results to return (1-10, default: 3)
//
// Returns:
//   - string: Formatted search results
//   - error: If search fails
func (h *Handler) SearchDocuments(ctx *ai.ToolContext, query string, topK int32) (string, error) {
	// No nil check needed - RegisterTools guarantees non-nil knowledgeStore

	// Validate and set defaults for topK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with file filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", "file"),
	}

	// Execute search
	results, err := h.knowledgeStore.Search(ctx.Context, query, opts...)
	if err != nil {
		return "", fmt.Errorf("document search failed: %w", err)
	}

	formatted := formatDocumentResults(results)
	return formatted, nil
}

// SearchSystemKnowledge searches system knowledge base using semantic similarity.
// Searches only system knowledge (source_type="system").
// Returns formatted results with similarity scores and metadata.
//
// Parameters:
//   - ctx: Tool execution context
//   - query: Search query string
//   - topK: Maximum results to return (1-10, default: 3)
//
// Returns:
//   - string: Formatted search results
//   - error: If search fails
func (h *Handler) SearchSystemKnowledge(ctx *ai.ToolContext, query string, topK int32) (string, error) {
	// No nil check needed - RegisterTools guarantees non-nil knowledgeStore

	// Validate and set defaults for topK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with system filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", "system"),
	}

	// Execute search
	results, err := h.knowledgeStore.Search(ctx.Context, query, opts...)
	if err != nil {
		return "", fmt.Errorf("system knowledge search failed: %w", err)
	}

	// UX Improvement (P2-Phase3): Check if system knowledge is indexed when results are empty
	if len(results) == 0 {
		// Use larger TopK to check if ANY system knowledge exists
		checkOpts := []knowledge.SearchOption{
			knowledge.WithTopK(10),
			knowledge.WithFilter("source_type", "system"),
		}
		allSystemDocs, checkErr := h.knowledgeStore.Search(ctx.Context, "system", checkOpts...)

		// Provide feedback if the check itself failed
		if checkErr != nil {
			return "Unable to check system knowledge status: " + checkErr.Error() + ". " +
				"System knowledge search may be experiencing issues. " +
				"You can try reindexing using `/rag reindex-system` command.", nil
		}

		// If no system documents found at all, warn the user
		if len(allSystemDocs) == 0 {
			return "No system knowledge found. System knowledge may not be indexed yet. " +
				"This could happen if the application just started or if indexing failed. " +
				"You can manually reindex using `/rag reindex-system` command.", nil
		}
	}

	return formatSystemResults(results), nil
}
