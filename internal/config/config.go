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

	// ErrConfigParse indicates configuration parsing failed.
	ErrConfigParse = errors.New("failed to parse configuration")

	// ErrInvalidPostgresPassword indicates the PostgreSQL password is invalid.
	ErrInvalidPostgresPassword = errors.New("invalid PostgreSQL password")

	// ErrInvalidPostgresSSLMode indicates the PostgreSQL SSL mode is invalid.
	ErrInvalidPostgresSSLMode = errors.New("invalid PostgreSQL SSL mode")
)

// ============================================================================
// Constants
// ============================================================================

const (
	// DefaultEmbedderModel is the default embedder model for vector embeddings.
	DefaultEmbedderModel = "text-embedding-004"

	// DefaultMaxHistoryMessages is the default number of messages to load.
	DefaultMaxHistoryMessages int32 = 100

	// MaxAllowedHistoryMessages is the absolute maximum to prevent OOM.
	MaxAllowedHistoryMessages int32 = 10000

	// MinHistoryMessages is the minimum allowed value for MaxHistoryMessages.
	MinHistoryMessages int32 = 10
)

// ============================================================================
// Config Struct
// ============================================================================

// Config stores application configuration.
// SECURITY: Sensitive fields are explicitly masked in MarshalJSON().
// When adding new sensitive fields (passwords, API keys, tokens), update MarshalJSON.
type Config struct {
	// AI configuration (see ai.go for documentation)
	ModelName   string  `mapstructure:"model_name" json:"model_name"`
	Temperature float32 `mapstructure:"temperature" json:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens" json:"max_tokens"`
	Language    string  `mapstructure:"language" json:"language"`
	PromptDir   string  `mapstructure:"prompt_dir" json:"prompt_dir"`

	// Conversation history configuration
	MaxHistoryMessages int32 `mapstructure:"max_history_messages" json:"max_history_messages"`
	MaxTurns           int   `mapstructure:"max_turns" json:"max_turns"`

	// Storage configuration (see storage.go for documentation)
	DatabasePath     string `mapstructure:"database_path" json:"database_path"`
	PostgresHost     string `mapstructure:"postgres_host" json:"postgres_host"`
	PostgresPort     int    `mapstructure:"postgres_port" json:"postgres_port"`
	PostgresUser     string `mapstructure:"postgres_user" json:"postgres_user"`
	PostgresPassword string `mapstructure:"postgres_password" json:"postgres_password"` // SENSITIVE: masked in MarshalJSON
	PostgresDBName   string `mapstructure:"postgres_db_name" json:"postgres_db_name"`
	PostgresSSLMode  string `mapstructure:"postgres_ssl_mode" json:"postgres_ssl_mode"`

	// RAG configuration
	RAGTopK       int    `mapstructure:"rag_top_k" json:"rag_top_k"`
	EmbedderModel string `mapstructure:"embedder_model" json:"embedder_model"`

	// MCP configuration (see tools.go for type definitions)
	MCP        MCPConfig            `mapstructure:"mcp" json:"mcp"`
	MCPServers map[string]MCPServer `mapstructure:"mcp_servers" json:"mcp_servers"`

	// Tool configuration (see tools.go for type definitions)
	SearXNG    SearXNGConfig    `mapstructure:"searxng" json:"searxng"`
	WebScraper WebScraperConfig `mapstructure:"web_scraper" json:"web_scraper"`

	// Observability configuration (see observability.go for type definition)
	Datadog DatadogConfig `mapstructure:"datadog" json:"datadog"`

	// Security configuration (serve mode only)
	HMACSecret string `mapstructure:"hmac_secret" json:"hmac_secret"` // SENSITIVE: masked in MarshalJSON
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
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	configDir := filepath.Join(home, ".koopa")

	// Ensure directory exists (use 0750 permission for better security)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
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
		var configNotFound viper.ConfigFileNotFoundError
		if !errors.As(err, &configNotFound) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		slog.Debug("configuration file not found, using default values",
			"search_paths", []string{configDir, "."},
			"config_name", "config.yaml")
	}

	// Use Unmarshal to automatically map to struct (type-safe)
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Parse DATABASE_URL if set (highest priority for PostgreSQL config)
	if err := cfg.parseDatabaseURL(); err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_URL: %w", err)
	}

	// CRITICAL: Validate immediately (fail-fast)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
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
	viper.SetDefault("max_history_messages", DefaultMaxHistoryMessages)
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

// bindEnvVariables binds sensitive environment variables explicitly.
// Only 3 environment variables for secrets:
//  1. GEMINI_API_KEY - Read directly by Genkit (not via Viper), validated in cfg.Validate()
//  2. DD_API_KEY - Datadog API key (optional, for observability)
//  3. HMAC_SECRET - HMAC secret for CSRF protection (serve mode only)
func bindEnvVariables() {
	// Helper to panic on unexpected bind errors (hardcoded strings can't fail)
	// If this panics, it's a BUG in our code, not a runtime error
	mustBind := func(key, envVar string) {
		if err := viper.BindEnv(key, envVar); err != nil {
			panic(fmt.Sprintf("BUG: failed to bind %q to %q: %v", key, envVar, err))
		}
	}

	// Datadog API key (optional, for observability)
	mustBind("datadog.api_key", "DD_API_KEY")

	// HMAC secret (serve mode CSRF protection)
	mustBind("hmac_secret", "HMAC_SECRET")

	// NOTE: GEMINI_API_KEY is read directly by Genkit, not via Viper
	// Validation checks its presence in cfg.Validate()
}

// ============================================================================
// Sensitive Data Masking
// ============================================================================

// maskedValue is the placeholder for masked sensitive data.
// Using ████████ (full-width blocks U+2588) to avoid substring matching
// Previous attempts:
// - "****" failed: passwords with "*" leaked
// - "[REDACTED]" failed: passwords with "A", "D", "E", etc. leaked
const maskedValue = "████████"

// maskSecret masks a secret string for safe logging.
// Shows first 2 and last 2 characters, masks the rest.
// SECURITY: For secrets <=8 chars, fully masks to prevent substring attacks.
// For longer secrets, shows partial chars with unique separator.
//
// THREAT MODEL: This defends against accidental logging of real secrets.
// It is NOT cryptographically secure - if logs are compromised, rotate secrets.
// It does NOT defend against adversarially-crafted "passwords" like "\x96"
// specifically designed to bypass masking (unrealistic attack scenario).
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	// Fully mask short secrets to prevent substring matching attacks
	// Example attack: input "00***" → output "00******" contains "00***"
	if len(s) <= 8 {
		return maskedValue
	}
	// For longer secrets, show first/last 2 chars for debug utility
	// Example: "my_long_secret_key_123" → "my<████████>23"
	prefix := make([]byte, 2)
	suffix := make([]byte, 2)
	copy(prefix, s[:2])
	copy(suffix, s[len(s)-2:])
	return string(prefix) + "<" + maskedValue + ">" + string(suffix)
}

// MarshalJSON implements json.Marshaler with explicit sensitive field masking.
//
// Sensitive fields masked:
//   - PostgresPassword
//   - HMACSecret
//   - Datadog.APIKey (via DatadogConfig.MarshalJSON)
//   - MCPServers[*].Env (via MCPServer.MarshalJSON)
//
// When adding new sensitive fields, update this method or the nested struct's MarshalJSON.
// The compiler will remind you when tests fail.
func (c Config) MarshalJSON() ([]byte, error) {
	type alias Config
	a := alias(c)
	a.PostgresPassword = maskSecret(a.PostgresPassword)
	a.HMACSecret = maskSecret(a.HMACSecret)
	// Note: Datadog.APIKey and MCPServers[*].Env are handled by their own MarshalJSON
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return data, nil
}

// String implements Stringer to prevent accidental printing of secrets.
func (c Config) String() string {
	data, err := c.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("Config{error: %v}", err)
	}
	return string(data)
}
