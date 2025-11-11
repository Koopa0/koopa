package config

// config.go provides application configuration management with multi-source priority.
//
// Configuration sources (highest to lowest priority):
//   1. Environment variables (runtime override)
//   2. Config file (~/.koopa/config.yaml)
//   3. Default values (sensible defaults for quick start)
//
// Main configuration categories:
//   - AI: Model selection, temperature, max tokens, embedder
//   - Storage: SQLite database path, PostgreSQL connection (for pgvector)
//   - RAG: Number of documents to retrieve (RAGTopK)
//   - MCP: Model Context Protocol server management
//
// Security: Sensitive data (passwords) are never logged; config directory uses 0750 permissions.
// Validation: Comprehensive range checks (temperature, tokens, ports) with clear error messages.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/spf13/viper"
)

// Config stores application configuration
type Config struct {
	// AI configuration
	ModelName   string  `mapstructure:"model_name"`
	Temperature float32 `mapstructure:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens"`

	// Conversation history configuration
	MaxHistoryMessages int `mapstructure:"max_history_messages"` // Maximum number of conversation messages to retain (0 = unlimited)

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
	RAGTopK       int    `mapstructure:"rag_top_k"`      // Number of documents to retrieve for RAG (default: 3)
	EmbedderModel string `mapstructure:"embedder_model"` // Embedding model name

	// MCP (Model Context Protocol) configuration
	MCP        MCPConfig            `mapstructure:"mcp"`         // Global MCP settings
	MCPServers map[string]MCPServer `mapstructure:"mcp_servers"` // MCP server definitions
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
	viper.SetDefault("max_history_messages", 50) // Default: keep recent 50 messages (~25 conversation turns)
	viper.SetDefault("database_path", filepath.Join(configDir, "koopa.db"))

	// PostgreSQL defaults (matching docker-compose.yml)
	viper.SetDefault("postgres_host", "localhost")
	viper.SetDefault("postgres_port", 5432)
	viper.SetDefault("postgres_user", "koopa")
	viper.SetDefault("postgres_password", "koopa_dev_password")
	viper.SetDefault("postgres_db_name", "koopa")
	viper.SetDefault("postgres_ssl_mode", "disable")

	viper.SetDefault("rag_top_k", 3)                         // Default: retrieve top 3 documents
	viper.SetDefault("embedder_model", "text-embedding-004") // Default Google AI embedder

	// MCP defaults
	viper.SetDefault("mcp.timeout", 5) // Default: 5 seconds connection timeout
	// Note: mcp_servers has no default - must be explicitly configured

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

	// Environment variable settings (no prefix needed)
	// Configuration can be set via environment variables without KOOPA_ prefix
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

// PostgresConnectionString returns the PostgreSQL DSN
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

// Validate validates configuration values
func (c *Config) Validate() error {
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
