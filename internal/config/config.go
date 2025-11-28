// Package config provides application configuration management with multi-source priority.
//
// Configuration sources (highest to lowest priority):
//  1. Environment variables (runtime override)
//  2. Config file (~/.koopa/config.yaml)
//  3. Default values (sensible defaults for quick start)
//
// Main configuration categories:
//   - AI: Model selection, temperature, max tokens, embedder (see ai.go)
//   - Storage: SQLite database path, PostgreSQL connection (see storage.go)
//   - RAG: Number of documents to retrieve (RAGTopK)
//   - MCP: Model Context Protocol server management (see tools.go)
//   - Observability: Datadog APM tracing (see observability.go)
//
// Security: Sensitive data (passwords) are never logged; config directory uses 0750 permissions.
// Validation: Comprehensive range checks in validation.go with clear error messages.
//
// Error Handling:
//   - Uses sentinel errors for Go-idiomatic error checking with errors.Is()
//   - Wrap with context using fmt.Errorf("%w: details", ErrXxx)
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// ============================================================================
// Sentinel Errors
// ============================================================================

var (
	// ErrConfigNil indicates the configuration is nil.
	ErrConfigNil = errors.New("configuration is nil")

	// ErrMissingAPIKey indicates a required API key is missing.
	ErrMissingAPIKey = errors.New("missing API key")

	// ErrInvalidModelName indicates the model name is invalid.
	ErrInvalidModelName = errors.New("invalid model name")

	// ErrInvalidTemperature indicates the temperature value is out of range.
	ErrInvalidTemperature = errors.New("invalid temperature")

	// ErrInvalidMaxTokens indicates the max tokens value is out of range.
	ErrInvalidMaxTokens = errors.New("invalid max tokens")

	// ErrInvalidRAGTopK indicates the RAG top-k value is out of range.
	ErrInvalidRAGTopK = errors.New("invalid RAG top-k")

	// ErrInvalidEmbedderModel indicates the embedder model is invalid.
	ErrInvalidEmbedderModel = errors.New("invalid embedder model")

	// ErrInvalidPostgresHost indicates the PostgreSQL host is invalid.
	ErrInvalidPostgresHost = errors.New("invalid PostgreSQL host")

	// ErrInvalidPostgresPort indicates the PostgreSQL port is out of range.
	ErrInvalidPostgresPort = errors.New("invalid PostgreSQL port")

	// ErrInvalidPostgresDBName indicates the PostgreSQL database name is invalid.
	ErrInvalidPostgresDBName = errors.New("invalid PostgreSQL database name")

	// ErrInvalidBranch indicates the branch name is invalid.
	ErrInvalidBranch = errors.New("invalid branch")

	// ErrBranchTooLong indicates the branch name exceeds maximum length.
	ErrBranchTooLong = errors.New("branch name too long")

	// ErrBranchTooDeep indicates the branch depth exceeds maximum.
	ErrBranchTooDeep = errors.New("branch depth too deep")

	// ErrConfigParse indicates configuration parsing failed.
	ErrConfigParse = errors.New("failed to parse configuration")
)

// ============================================================================
// Constants
// ============================================================================

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

// ============================================================================
// Config Struct
// ============================================================================

// Config stores application configuration.
type Config struct {
	// AI configuration (see ai.go for documentation)
	ModelName   string  `mapstructure:"model_name"`
	Temperature float32 `mapstructure:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens"`
	Language    string  `mapstructure:"language"`
	PromptDir   string  `mapstructure:"prompt_dir"`

	// Conversation history configuration
	MaxHistoryMessages int32 `mapstructure:"max_history_messages"`
	MaxTurns           int   `mapstructure:"max_turns"`

	// Storage configuration (see storage.go for documentation)
	DatabasePath     string `mapstructure:"database_path"`
	PostgresHost     string `mapstructure:"postgres_host"`
	PostgresPort     int    `mapstructure:"postgres_port"`
	PostgresUser     string `mapstructure:"postgres_user"`
	PostgresPassword string `mapstructure:"postgres_password"`
	PostgresDBName   string `mapstructure:"postgres_db_name"`
	PostgresSSLMode  string `mapstructure:"postgres_ssl_mode"`

	// RAG configuration
	RAGTopK       int32  `mapstructure:"rag_top_k"`
	EmbedderModel string `mapstructure:"embedder_model"`

	// MCP configuration (see tools.go for type definitions)
	MCP        MCPConfig            `mapstructure:"mcp"`
	MCPServers map[string]MCPServer `mapstructure:"mcp_servers"`

	// Tool configuration (see tools.go for type definitions)
	SearXNG    SearXNGConfig    `mapstructure:"searxng"`
	WebScraper WebScraperConfig `mapstructure:"web_scraper"`

	// Observability configuration (see observability.go for type definition)
	Datadog DatadogConfig `mapstructure:"datadog"`
}

// ============================================================================
// Load Function
// ============================================================================

// Load loads configuration.
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
	setDefaults(configDir)

	// Bind environment variables
	bindEnvVariables()

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

// setDefaults sets all default configuration values.
func setDefaults(configDir string) {
	// AI defaults
	viper.SetDefault("model_name", "gemini-2.5-flash")
	viper.SetDefault("temperature", 0.7)
	viper.SetDefault("max_tokens", 2048)
	viper.SetDefault("language", "auto")
	viper.SetDefault("max_history_messages", 50)
	viper.SetDefault("max_turns", 5)
	viper.SetDefault("database_path", filepath.Join(configDir, "koopa.db"))

	// PostgreSQL defaults (matching docker-compose.yml)
	viper.SetDefault("postgres_host", "localhost")
	viper.SetDefault("postgres_port", 5432)
	viper.SetDefault("postgres_user", "koopa")
	viper.SetDefault("postgres_password", "koopa_dev_password")
	viper.SetDefault("postgres_db_name", "koopa")
	viper.SetDefault("postgres_ssl_mode", "disable")

	// RAG defaults
	viper.SetDefault("rag_top_k", 3)
	viper.SetDefault("embedder_model", DefaultEmbedderModel)

	// MCP defaults
	viper.SetDefault("mcp.timeout", 5)

	// SearXNG defaults
	viper.SetDefault("searxng.base_url", "http://localhost:8888")

	// WebScraper defaults
	viper.SetDefault("web_scraper.parallelism", 2)
	viper.SetDefault("web_scraper.delay_ms", 1000)
	viper.SetDefault("web_scraper.timeout_ms", 30000)

	// Datadog defaults
	viper.SetDefault("datadog.agent_host", "localhost:4318")
	viper.SetDefault("datadog.environment", "dev")
	viper.SetDefault("datadog.service_name", "koopa")
}

// bindEnvVariables binds specific environment variables.
func bindEnvVariables() {
	// Datadog environment variables
	_ = viper.BindEnv("datadog.agent_host", "DD_AGENT_HOST")
	_ = viper.BindEnv("datadog.environment", "DD_ENV")
	_ = viper.BindEnv("datadog.service_name", "DD_SERVICE")
}

// ============================================================================
// Sensitive Data Masking
// ============================================================================

// maskSecret masks a secret string for safe logging.
// Shows first 2 and last 2 characters, masks the rest.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// MarshalJSON implements custom JSON marshaling to mask sensitive fields.
// This prevents accidental leakage if Config is logged or serialized.
func (c Config) MarshalJSON() ([]byte, error) {
	// Create an alias to avoid infinite recursion
	type Alias Config
	return json.Marshal(&struct {
		PostgresPassword string `json:"postgres_password"`
		*Alias
	}{
		PostgresPassword: maskSecret(c.PostgresPassword),
		Alias:            (*Alias)(&c),
	})
}

// String implements Stringer to prevent accidental printing of secrets.
func (c Config) String() string {
	data, err := c.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("Config{error: %v}", err)
	}
	return string(data)
}
