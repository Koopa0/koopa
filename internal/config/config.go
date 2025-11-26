// Package config provides application configuration management with multi-source priority.
//
// Configuration sources (highest to lowest priority):
//  1. Environment variables (runtime override)
//  2. Config file (~/.koopa/config.yaml)
//  3. Default values (sensible defaults for quick start)
//
// Main configuration categories:
//   - AI: Model selection, temperature, max tokens, embedder
//   - Storage: SQLite database path, PostgreSQL connection (for pgvector)
//   - RAG: Number of documents to retrieve (RAGTopK)
//   - MCP: Model Context Protocol server management
//
// Security: Sensitive data (passwords) are never logged; config directory uses 0750 permissions.
// Validation: Comprehensive range checks (temperature, tokens, ports) with clear error messages.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/spf13/viper"
)

// Default configuration constants.
const (
	// DefaultEmbedderModel is the default embedder model for vector embeddings.
	DefaultEmbedderModel = "text-embedding-004"

	// DefaultMaxHistoryMessages is the default number of messages to load per branch.
	DefaultMaxHistoryMessages int32 = 100

	// MaxAllowedHistoryMessages is the absolute maximum to prevent OOM.
	MaxAllowedHistoryMessages int32 = 10000

	// MinHistoryMessages is the minimum allowed value for MaxHistoryMessages.
	MinHistoryMessages int32 = 10

	// DefaultBranch is the default branch name for conversation history.
	DefaultBranch = "main"

	// MaxBranchLength is the maximum allowed length for branch names.
	MaxBranchLength = 256

	// MaxBranchDepth is the maximum nesting depth for branches (e.g., "main.a.b.c" = 4).
	MaxBranchDepth = 10
)

// Config stores application configuration
type Config struct {
	// AI configuration
	ModelName   string  `mapstructure:"model_name"`
	Temperature float32 `mapstructure:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens"`
	Language    string  `mapstructure:"language"`   // Response language: "auto", "English", "zh-TW"
	PromptDir   string  `mapstructure:"prompt_dir"` // Directory containing .prompt files for Dotprompt

	// Conversation history configuration
	MaxHistoryMessages int32 `mapstructure:"max_history_messages"` // Maximum number of conversation messages to retain (0 = unlimited)
	MaxTurns           int   `mapstructure:"max_turns"`            // Maximum number of autonomous execution turns

	// Storage configuration
	DatabasePath string `mapstructure:"database_path"` // SQLite database path

	// PostgreSQL configuration (for pgvector)
	PostgresHost     string `mapstructure:"postgres_host"`
	PostgresPort     int    `mapstructure:"postgres_port"`
	PostgresUser     string `mapstructure:"postgres_user"`
	PostgresPassword string `mapstructure:"postgres_password"`
	PostgresDBName   string `mapstructure:"postgres_db_name"`
	PostgresSSLMode  string `mapstructure:"postgres_ssl_mode"`

	// RAG (Retrieval-Augmented Generation) configuration
	RAGTopK       int32  `mapstructure:"rag_top_k"`      // Number of documents to retrieve for RAG (default: 3)
	EmbedderModel string `mapstructure:"embedder_model"` // Embedding model name

	// MCP (Model Context Protocol) configuration
	MCP        MCPConfig            `mapstructure:"mcp"`         // Global MCP settings
	MCPServers map[string]MCPServer `mapstructure:"mcp_servers"` // MCP server definitions

	// SearXNG configuration (web search)
	SearXNG SearXNGConfig `mapstructure:"searxng"`

	// WebScraper configuration (web fetching)
	WebScraper WebScraperConfig `mapstructure:"web_scraper"`
}

// SearXNGConfig holds SearXNG service configuration.
type SearXNGConfig struct {
	// BaseURL is the SearXNG instance URL (e.g., http://searxng:8080)
	BaseURL string `mapstructure:"base_url"`
}

// WebScraperConfig holds web scraper configuration.
type WebScraperConfig struct {
	// Parallelism is max concurrent requests per domain (default: 2)
	Parallelism int `mapstructure:"parallelism"`
	// DelayMs is delay between requests in milliseconds (default: 1000)
	DelayMs int `mapstructure:"delay_ms"`
	// TimeoutMs is request timeout in milliseconds (default: 30000)
	TimeoutMs int `mapstructure:"timeout_ms"`
}

// MCPConfig controls global MCP behavior
type MCPConfig struct {
	Allowed  []string `mapstructure:"allowed"`  // Whitelist of server names (empty = all configured servers)
	Excluded []string `mapstructure:"excluded"` // Blacklist of server names (higher priority than Allowed)
	Timeout  int      `mapstructure:"timeout"`  // Connection timeout in seconds (default: 5)
}

// MCPServer defines a single MCP server configuration
type MCPServer struct {
	Command      string            `mapstructure:"command"`       // Required: executable path (e.g., "npx")
	Args         []string          `mapstructure:"args"`          // Optional: command arguments
	Env          map[string]string `mapstructure:"env"`           // Optional: environment variables (supports $VAR_NAME syntax)
	Timeout      int               `mapstructure:"timeout"`       // Optional: per-server timeout (overrides global)
	IncludeTools []string          `mapstructure:"include_tools"` // Optional: tool whitelist
	ExcludeTools []string          `mapstructure:"exclude_tools"` // Optional: tool blacklist
}

// Load loads configuration
// Priority: Environment variables > Configuration file > Default values
func Load() (*Config, error) {
	// Configuration directory: ~/.koopa/
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(home, ".koopa")

	// Ensure directory exists (use 0750 permission for better security)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return nil, err
	}

	// Configure Viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".") // Also support current directory

	// Set default values
	viper.SetDefault("model_name", "gemini-2.5-flash")
	viper.SetDefault("temperature", 0.7)
	viper.SetDefault("max_tokens", 2048)
	viper.SetDefault("language", "auto")         // Default: auto-detect language from user input
	viper.SetDefault("max_history_messages", 50) // Default: keep recent 50 messages (~25 conversation turns)
	viper.SetDefault("max_turns", 5)             // Default: 5 autonomous turns
	viper.SetDefault("database_path", filepath.Join(configDir, "koopa.db"))

	// PostgreSQL defaults (matching docker-compose.yml)
	viper.SetDefault("postgres_host", "localhost")
	viper.SetDefault("postgres_port", 5432)
	viper.SetDefault("postgres_user", "koopa")
	viper.SetDefault("postgres_password", "koopa_dev_password")
	viper.SetDefault("postgres_db_name", "koopa")
	viper.SetDefault("postgres_ssl_mode", "disable")

	viper.SetDefault("rag_top_k", 3)                         // Default: retrieve top 3 documents
	viper.SetDefault("embedder_model", DefaultEmbedderModel) // Default Google AI embedder

	// MCP defaults
	viper.SetDefault("mcp.timeout", 5) // Default: 5 seconds connection timeout
	// Note: mcp_servers has no default - must be explicitly configured

	// SearXNG defaults (required for web search capability)
	viper.SetDefault("searxng.base_url", "http://searxng:8080")

	// WebScraper defaults
	viper.SetDefault("web_scraper.parallelism", 2)
	viper.SetDefault("web_scraper.delay_ms", 1000)
	viper.SetDefault("web_scraper.timeout_ms", 30000)

	// Read configuration file (if exists)
	if err := viper.ReadInConfig(); err != nil {
		// Configuration file not found is not an error, use default values
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Debug("configuration file not found, using default values",
				"search_paths", []string{configDir, "."},
				"config_name", "config.yaml")
		} else {
			return nil, err
		}
	}

	// Environment variable settings with KOOPA_ prefix to avoid collisions
	// e.g., KOOPA_MODEL_NAME, KOOPA_DATABASE_PATH
	viper.SetEnvPrefix("KOOPA")
	viper.AutomaticEnv()

	// Use Unmarshal to automatically map to struct (type-safe)
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &cfg, nil
}

// Plugins returns Genkit plugins for this configuration.
func (c *Config) Plugins() []any {
	return []any{&googlegenai.GoogleAI{}}
}

// PostgresConnectionString returns the PostgreSQL DSN for pgx driver
func (c *Config) PostgresConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresDBName,
		c.PostgresSSLMode,
	)
}

// PostgresURL returns the PostgreSQL URL for golang-migrate
func (c *Config) PostgresURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresDBName,
		c.PostgresSSLMode,
	)
}

// Validate validates configuration values
func (c *Config) Validate() error {
	// 0. Check for nil config (defensive programming)
	if c == nil {
		return &ConfigError{
			Field:   "config",
			Message: "Configuration is nil",
		}
	}

	// 1. API Key validation (required for all AI operations)
	if os.Getenv("GEMINI_API_KEY") == "" {
		return &ConfigError{
			Field:   "GEMINI_API_KEY",
			Message: "Gemini API key is required. Set GEMINI_API_KEY environment variable.",
		}
	}

	// 2. Model configuration validation
	if c.ModelName == "" {
		return &ConfigError{
			Field:   "model_name",
			Message: "Model name cannot be empty. Set model_name in config file or MODEL_NAME environment variable.",
		}
	}

	// Temperature range: 0.0 (deterministic) to 2.0 (maximum creativity)
	// Reference: Gemini API documentation
	if c.Temperature < 0.0 || c.Temperature > 2.0 {
		return &ConfigError{
			Field:   "temperature",
			Message: fmt.Sprintf("Temperature must be between 0.0 and 2.0, got %.2f", c.Temperature),
		}
	}

	// MaxTokens range: 1 to 2097152 (Gemini 2.5 max context window)
	// Reference: https://ai.google.dev/gemini-api/docs/models
	if c.MaxTokens < 1 || c.MaxTokens > 2097152 {
		return &ConfigError{
			Field:   "max_tokens",
			Message: fmt.Sprintf("MaxTokens must be between 1 and 2,097,152, got %d", c.MaxTokens),
		}
	}

	// 3. RAG configuration validation
	if c.RAGTopK <= 0 || c.RAGTopK > 10 {
		return &ConfigError{
			Field:   "rag_top_k",
			Message: fmt.Sprintf("RAGTopK must be between 1 and 10, got %d", c.RAGTopK),
		}
	}

	if c.EmbedderModel == "" {
		return &ConfigError{
			Field:   "embedder_model",
			Message: "Embedder model cannot be empty. Set embedder_model in config file.",
		}
	}

	// 4. PostgreSQL configuration validation
	if c.PostgresHost == "" {
		return &ConfigError{
			Field:   "postgres_host",
			Message: "PostgreSQL host cannot be empty.",
		}
	}

	if c.PostgresPort < 1 || c.PostgresPort > 65535 {
		return &ConfigError{
			Field:   "postgres_port",
			Message: fmt.Sprintf("PostgreSQL port must be between 1 and 65535, got %d", c.PostgresPort),
		}
	}

	if c.PostgresDBName == "" {
		return &ConfigError{
			Field:   "postgres_db_name",
			Message: "PostgreSQL database name cannot be empty.",
		}
	}

	return nil
}

// ConfigError represents a configuration error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// BranchError represents a branch validation error.
type BranchError struct {
	Branch  string
	Message string
}

func (e *BranchError) Error() string {
	return fmt.Sprintf("invalid branch %q: %s", e.Branch, e.Message)
}

// ValidateBranch validates a branch name according to the following rules:
//   - Branch format: "segment" or "segment1.segment2.segment3"
//   - Each segment must start with a letter and contain only alphanumeric chars and underscores
//   - Maximum total length is MaxBranchLength (256)
//   - Maximum depth is MaxBranchDepth (10 segments)
//   - Empty branch defaults to DefaultBranch ("main")
//
// Examples of valid branches: "main", "main.research", "chat.agent1.subtask"
// Examples of invalid branches: ".main", "main.", "main..sub", "123abc"
func ValidateBranch(branch string) (string, error) {
	if branch == "" {
		return DefaultBranch, nil
	}

	if len(branch) > MaxBranchLength {
		return "", &BranchError{
			Branch:  branch,
			Message: fmt.Sprintf("branch name too long (max %d characters)", MaxBranchLength),
		}
	}

	segments := splitBranch(branch)
	if len(segments) > MaxBranchDepth {
		return "", &BranchError{
			Branch:  branch,
			Message: fmt.Sprintf("branch depth too deep (max %d levels)", MaxBranchDepth),
		}
	}

	for i, seg := range segments {
		if seg == "" {
			return "", &BranchError{
				Branch:  branch,
				Message: "empty segment (consecutive dots or leading/trailing dot)",
			}
		}
		if !isValidSegment(seg) {
			return "", &BranchError{
				Branch:  branch,
				Message: fmt.Sprintf("segment %d %q must start with a letter and contain only alphanumeric characters and underscores", i+1, seg),
			}
		}
	}

	return branch, nil
}

// splitBranch splits a branch name by dots.
func splitBranch(branch string) []string {
	if branch == "" {
		return nil
	}

	var segments []string
	start := 0
	for i := 0; i < len(branch); i++ {
		if branch[i] == '.' {
			segments = append(segments, branch[start:i])
			start = i + 1
		}
	}
	segments = append(segments, branch[start:])
	return segments
}

// isValidSegment checks if a branch segment is valid.
func isValidSegment(seg string) bool {
	if len(seg) == 0 {
		return false
	}

	// First character must be a letter (De Morgan's law applied)
	first := seg[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return false
	}

	// Remaining characters must be alphanumeric or underscore (De Morgan's law applied)
	for i := 1; i < len(seg); i++ {
		c := seg[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}

	return true
}

// NormalizeBranch normalizes and validates a branch name.
func NormalizeBranch(branch string) (string, error) {
	return ValidateBranch(branch)
}

// NormalizeMaxHistoryMessages normalizes the max history messages value.
func NormalizeMaxHistoryMessages(limit int32) int32 {
	if limit <= 0 {
		return DefaultMaxHistoryMessages
	}
	if limit < MinHistoryMessages {
		return MinHistoryMessages
	}
	if limit > MaxAllowedHistoryMessages {
		return MaxAllowedHistoryMessages
	}
	return limit
}
