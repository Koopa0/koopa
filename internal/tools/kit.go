package tools

import (
	"context"
	"fmt"
	"net/http"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
)

// HTTPValidator defines HTTP security validation interface.
type HTTPValidator interface {
	// ValidateURL validates a URL to prevent SSRF attacks
	ValidateURL(url string) error

	// Client returns a configured HTTP client
	Client() *http.Client

	// MaxResponseSize returns the maximum allowed response size in bytes
	MaxResponseSize() int64
}

// KnowledgeSearcher defines knowledge search interface.
type KnowledgeSearcher interface {
	// Search performs semantic search on knowledge documents
	Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error)
}

// Logger defines logging interface (optional).
type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// KitConfig holds all required dependencies for Kit.
type KitConfig struct {
	PathVal        *security.Path
	CmdVal         *security.Command
	EnvVal         *security.Env
	HTTPVal        HTTPValidator
	KnowledgeStore KnowledgeSearcher
}

// Kit provides a collection of tools for AI agents.
type Kit struct {
	pathVal        *security.Path
	cmdVal         *security.Command
	envVal         *security.Env
	httpVal        HTTPValidator
	knowledgeStore KnowledgeSearcher
	logger         Logger
}

// Option is a functional option for configuring optional Kit features.
type Option func(*Kit) error

// WithLogger sets an optional logger.
func WithLogger(logger Logger) Option {
	return func(k *Kit) error {
		k.logger = logger
		return nil
	}
}

// NewKit creates a new tool kit with all required dependencies.
func NewKit(cfg KitConfig, opts ...Option) (*Kit, error) {
	// Validate all required dependencies
	if cfg.PathVal == nil {
		return nil, fmt.Errorf("KitConfig.PathVal is required")
	}
	if cfg.CmdVal == nil {
		return nil, fmt.Errorf("KitConfig.CmdVal is required")
	}
	if cfg.EnvVal == nil {
		return nil, fmt.Errorf("KitConfig.EnvVal is required")
	}
	if cfg.HTTPVal == nil {
		return nil, fmt.Errorf("KitConfig.HTTPVal is required")
	}
	if cfg.KnowledgeStore == nil {
		return nil, fmt.Errorf("KitConfig.KnowledgeStore is required")
	}

	kit := &Kit{
		pathVal:        cfg.PathVal,
		cmdVal:         cfg.CmdVal,
		envVal:         cfg.EnvVal,
		httpVal:        cfg.HTTPVal,
		knowledgeStore: cfg.KnowledgeStore,
	}

	// Apply optional features
	for _, opt := range opts {
		if err := opt(kit); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return kit, nil
}

// Register registers all tools from the Kit to Genkit.
func (k *Kit) Register(g *genkit.Genkit) error {
	if g == nil {
		return fmt.Errorf("genkit instance is required (cannot be nil)")
	}

	k.log("info", "Registering all tools to Genkit")

	// Register tools by category
	if err := k.registerFileTools(g); err != nil {
		return fmt.Errorf("register file tools: %w", err)
	}
	if err := k.registerSystemTools(g); err != nil {
		return fmt.Errorf("register system tools: %w", err)
	}
	if err := k.registerNetworkTools(g); err != nil {
		return fmt.Errorf("register network tools: %w", err)
	}
	if err := k.registerKnowledgeTools(g); err != nil {
		return fmt.Errorf("register knowledge tools: %w", err)
	}

	k.log("info", "All tools registered successfully")
	return nil
}

// log is a helper to log if logger is configured.
func (k *Kit) log(level string, msg string, args ...any) {
	if k.logger != nil {
		switch level {
		case "info":
			k.logger.Info(msg, args...)
		case "error":
			k.logger.Error(msg, args...)
		}
	}
}

// registerFileTools registers all file operation tools to Genkit.
func (k *Kit) registerFileTools(g *genkit.Genkit) error {
	k.log("info", "Registering file tools")

	genkit.DefineTool(g, "readFile",
		"Read the complete content of any text-based file. "+
			"Use this to analyze source code, read documentation, check configuration files, or review logs. "+
			"Supports absolute and relative paths. Validates paths for security. "+
			"Returns the full text content of the file.",
		k.ReadFile)

	genkit.DefineTool(g, "writeFile",
		"Write or create any text-based file with the specified content. "+
			"Use this to create new files, save generated content, or update existing files. "+
			"WARNING: This will overwrite existing files! Automatically creates parent directories.",
		k.WriteFile)

	genkit.DefineTool(g, "listFiles",
		"List all files and subdirectories in a directory. "+
			"Use this to explore directory structure, find files of specific types, or understand project organization.",
		k.ListFiles)

	genkit.DefineTool(g, "deleteFile",
		"Delete a file permanently from the filesystem. "+
			"WARNING: This action is irreversible! File will be permanently deleted.",
		k.DeleteFile)

	genkit.DefineTool(g, "getFileInfo",
		"Get detailed metadata about a file or directory without reading its content. "+
			"Returns: name, size, type (file/directory), modification time, permissions.",
		k.GetFileInfo)

	return nil
}

// registerSystemTools registers all system operation tools to Genkit.
func (k *Kit) registerSystemTools(g *genkit.Genkit) error {
	k.log("info", "Registering system tools")

	genkit.DefineTool(g, "currentTime",
		"Get the current system date and time. "+
			"Returns the current timestamp in human-readable format with date, time, and day of week.",
		k.CurrentTime)

	genkit.DefineTool(g, "executeCommand",
		"Execute a system shell command with security validation. "+
			"WARNING: Dangerous commands (rm -rf, dd, format, etc.) are automatically blocked for safety.",
		k.ExecuteCommand)

	genkit.DefineTool(g, "getEnv",
		"Read an environment variable value with security protection. "+
			"Sensitive variables (API keys, passwords, tokens) are automatically blocked to prevent information leakage.",
		k.GetEnv)

	return nil
}

// registerNetworkTools registers all network operation tools to Genkit.
func (k *Kit) registerNetworkTools(g *genkit.Genkit) error {
	k.log("info", "Registering network tools")

	genkit.DefineTool(g, "httpGet",
		"Send an HTTP GET request to a URL with comprehensive security protection. "+
			"Security features: SSRF protection (blocks internal IPs, localhost, metadata services), response size limits, timeout protection.",
		k.HTTPGet)

	return nil
}

// registerKnowledgeTools registers all knowledge search tools to Genkit.
func (k *Kit) registerKnowledgeTools(g *genkit.Genkit) error {
	k.log("info", "Registering knowledge tools")

	genkit.DefineTool(g, "searchHistory",
		"Search conversation history to find previous discussions, topics, or context from past interactions. "+
			"Use this to recall what the user said before, find previous answers you gave, or understand context from earlier in the conversation.",
		k.SearchHistory)

	genkit.DefineTool(g, "searchDocuments",
		"Search indexed documents and files to find relevant information from the user's knowledge base. "+
			"Use this to find information from documentation, source code, notes, or any files the user has indexed.",
		k.SearchDocuments)

	genkit.DefineTool(g, "searchSystemKnowledge",
		"Search system knowledge base to find best practices, style guides, coding standards, and framework-specific guidance. "+
			"Use this to understand how to write code correctly in this project, follow established patterns, or look up system capabilities.",
		k.SearchSystemKnowledge)

	return nil
}

// All returns all registered tools from Genkit.
// This is used by the Agent to get tool references for execution.
//
// V3.0 Design: We DO NOT maintain any tool list (global or local).
// Instead, we use Genkit's ListTools() API to get all registered tools.
// Genkit manages the tool registry internally.
//
// This method simply converts []ai.Tool to []ai.ToolRef for Agent compatibility.
func (k *Kit) All(ctx context.Context, g *genkit.Genkit) []ai.ToolRef {
	// Use Genkit's ListTools() to get all registered tools
	// This eliminates the need to manually maintain a tool list
	tools := genkit.ListTools(g)

	toolRefs := make([]ai.ToolRef, len(tools))
	for i, tool := range tools {
		toolRefs[i] = tool
	}

	return toolRefs
}
