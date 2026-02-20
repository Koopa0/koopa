// Package config provides application configuration management with multi-source priority.
//
// Configuration sources (highest to lowest priority):
//  1. Environment variables (runtime override)
//  2. Config file (~/.koopa/config.yaml)
//  3. Default values (sensible defaults for quick start)
//
// Main configuration categories:
//   - AI: Model selection, temperature, max tokens, embedder
//   - Storage: PostgreSQL connection (see storage.go)
//   - RAG: Embedder model for vector embeddings
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
	"strings"

	"github.com/spf13/viper"
)

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

	// ErrInvalidEmbedderModel indicates the embedder model is invalid.
	ErrInvalidEmbedderModel = errors.New("invalid embedder model")

	// ErrInvalidEmbedderDimension indicates the embedder produces incompatible vector dimensions.
	ErrInvalidEmbedderDimension = errors.New("incompatible embedder dimension")

	// ErrInvalidPostgresHost indicates the PostgreSQL host is invalid.
	ErrInvalidPostgresHost = errors.New("invalid PostgreSQL host")

	// ErrInvalidPostgresPort indicates the PostgreSQL port is out of range.
	ErrInvalidPostgresPort = errors.New("invalid PostgreSQL port")

	// ErrInvalidPostgresDBName indicates the PostgreSQL database name is invalid.
	ErrInvalidPostgresDBName = errors.New("invalid PostgreSQL database name")

	// ErrInvalidProvider indicates the AI provider is not supported.
	ErrInvalidProvider = errors.New("invalid provider")

	// ErrInvalidOllamaHost indicates the Ollama host is invalid.
	ErrInvalidOllamaHost = errors.New("invalid Ollama host")

	// ErrInvalidPostgresPassword indicates the PostgreSQL password is invalid.
	ErrInvalidPostgresPassword = errors.New("invalid PostgreSQL password")

	// ErrInvalidPostgresSSLMode indicates the PostgreSQL SSL mode is invalid.
	ErrInvalidPostgresSSLMode = errors.New("invalid PostgreSQL SSL mode")

	// ErrMissingHMACSecret indicates the HMAC secret is not set.
	ErrMissingHMACSecret = errors.New("missing HMAC secret")

	// ErrInvalidHMACSecret indicates the HMAC secret is too short.
	ErrInvalidHMACSecret = errors.New("invalid HMAC secret")

	// ErrDefaultPassword indicates a default development password is used in serve mode.
	ErrDefaultPassword = errors.New("default password in serve mode")

	// ErrInvalidRetentionDays indicates the retention days value is out of range.
	ErrInvalidRetentionDays = errors.New("invalid retention days")
)

const (
	// DefaultGeminiEmbedderModel is the default Gemini embedder model.
	// gemini-embedding-001 outputs 3072 dimensions by default, but supports
	// truncation to 768 via OutputDimensionality (Matryoshka Representation Learning).
	// Our pgvector schema uses 768 dimensions; see rag.VectorDimension.
	DefaultGeminiEmbedderModel = "gemini-embedding-001"

	// DefaultMaxHistoryMessages is the default number of messages to load.
	DefaultMaxHistoryMessages int32 = 100

	// MaxAllowedHistoryMessages is the absolute maximum to prevent OOM.
	MaxAllowedHistoryMessages int32 = 10000

	// MinHistoryMessages is the minimum allowed value for MaxHistoryMessages.
	MinHistoryMessages int32 = 10
)

// AI provider identifiers used in Config.Provider.
const (
	ProviderGemini   = "gemini"
	ProviderOllama   = "ollama"
	ProviderOpenAI   = "openai"
	ProviderGoogleAI = "googleai"
)

// Config stores application configuration.
// SECURITY: Sensitive fields are explicitly masked in MarshalJSON().
// When adding new sensitive fields (passwords, API keys, tokens), update MarshalJSON.
type Config struct {
	// AI provider and model configuration
	Provider    string  `mapstructure:"provider" json:"provider"`     // "gemini" (default), "ollama", "openai"
	ModelName   string  `mapstructure:"model_name" json:"model_name"` // Model identifier (e.g., "gemini-2.5-flash", "llama3.3", "gpt-4o")
	Temperature float32 `mapstructure:"temperature" json:"temperature"`
	MaxTokens   int     `mapstructure:"max_tokens" json:"max_tokens"`
	Language    string  `mapstructure:"language" json:"language"`
	PromptDir   string  `mapstructure:"prompt_dir" json:"prompt_dir"`

	// Ollama configuration (only used when provider is "ollama")
	OllamaHost string `mapstructure:"ollama_host" json:"ollama_host"`

	// Conversation history configuration
	MaxHistoryMessages int32 `mapstructure:"max_history_messages" json:"max_history_messages"`
	MaxTurns           int   `mapstructure:"max_turns" json:"max_turns"`

	// Storage configuration (see storage.go for documentation)
	PostgresHost     string `mapstructure:"postgres_host" json:"postgres_host"`
	PostgresPort     int    `mapstructure:"postgres_port" json:"postgres_port"`
	PostgresUser     string `mapstructure:"postgres_user" json:"postgres_user"`
	PostgresPassword string `mapstructure:"postgres_password" json:"postgres_password"` // SENSITIVE: masked in MarshalJSON
	PostgresDBName   string `mapstructure:"postgres_db_name" json:"postgres_db_name"`
	PostgresSSLMode  string `mapstructure:"postgres_ssl_mode" json:"postgres_ssl_mode"`

	// RAG configuration
	EmbedderModel string `mapstructure:"embedder_model" json:"embedder_model"`

	// Tool configuration (see tools.go for type definitions)
	SearXNG    SearXNGConfig    `mapstructure:"searxng" json:"searxng"`
	WebScraper WebScraperConfig `mapstructure:"web_scraper" json:"web_scraper"`

	// Observability configuration (see observability.go for type definition)
	Datadog DatadogConfig `mapstructure:"datadog" json:"datadog"`

	// Data lifecycle configuration
	RetentionDays int `mapstructure:"retention_days" json:"retention_days"` // Days to retain sessions (0 = no cleanup, default 365)

	// Security configuration (serve mode only)
	HMACSecret  string   `mapstructure:"hmac_secret" json:"hmac_secret"` // SENSITIVE: masked in MarshalJSON
	CORSOrigins []string `mapstructure:"cors_origins" json:"cors_origins"`
	TrustProxy  bool     `mapstructure:"trust_proxy" json:"trust_proxy"` // Trust X-Real-IP/X-Forwarded-For headers (set true behind reverse proxy)
	DevMode     bool     `mapstructure:"dev_mode" json:"dev_mode"`       // Dev mode: disables Secure flag on cookies (decoupled from DB SSL)
}

// Load loads configuration.
// Priority: Environment variables > Configuration file > Default values
func Load() (*Config, error) {
	// Configuration directory: ~/.koopa/
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting user home directory: %w", err)
	}

	configDir := filepath.Join(home, ".koopa")

	// Ensure directory exists (use 0750 permission for better security)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating config directory: %w", err)
	}

	// Use a viper instance instead of the global singleton.
	// This makes Load() safe for concurrent use and prevents test pollution.
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(configDir)
	v.AddConfigPath(".") // Also support current directory

	// Set default values
	setDefaults(v)

	// Bind environment variables
	bindEnvVariables(v)

	// Read configuration file (if exists)
	if err := v.ReadInConfig(); err != nil {
		// Configuration file not found is not an error, use default values
		var configNotFound viper.ConfigFileNotFoundError
		if !errors.As(err, &configNotFound) {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		slog.Debug("configuration file not found, using default values",
			"search_paths", []string{configDir, "."},
			"config_name", "config.yaml")
	}

	// Use Unmarshal to automatically map to struct (type-safe)
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing configuration: %w", err)
	}

	// Parse DATABASE_URL if set (highest priority for PostgreSQL config)
	if err := cfg.parseDatabaseURL(); err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}

	// CRITICAL: Validate immediately (fail-fast)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets all default configuration values on the given viper instance.
func setDefaults(v *viper.Viper) {
	// AI defaults
	v.SetDefault("provider", ProviderGemini)
	v.SetDefault("model_name", "gemini-2.5-flash")
	v.SetDefault("temperature", 0.7)
	v.SetDefault("max_tokens", 2048)
	v.SetDefault("language", "auto")
	v.SetDefault("max_history_messages", DefaultMaxHistoryMessages)
	v.SetDefault("max_turns", 5)

	// Ollama defaults
	v.SetDefault("ollama_host", "http://localhost:11434")
	// PostgreSQL defaults (matching docker-compose.yml)
	v.SetDefault("postgres_host", "localhost")
	v.SetDefault("postgres_port", 5432)
	v.SetDefault("postgres_user", "koopa")
	v.SetDefault("postgres_password", "koopa_dev_password")
	v.SetDefault("postgres_db_name", "koopa")
	v.SetDefault("postgres_ssl_mode", "disable")

	// RAG defaults
	v.SetDefault("embedder_model", DefaultGeminiEmbedderModel)

	// MCP defaults
	v.SetDefault("mcp.timeout", 5)

	// SearXNG defaults
	v.SetDefault("searxng.base_url", "http://localhost:8888")

	// WebScraper defaults
	v.SetDefault("web_scraper.parallelism", 2)
	v.SetDefault("web_scraper.delay_ms", 1000)
	v.SetDefault("web_scraper.timeout_ms", 30000)

	// Data lifecycle defaults
	v.SetDefault("retention_days", 365) // 1 year default

	// CORS defaults (Angular dev server)
	v.SetDefault("cors_origins", []string{"http://localhost:4200"})

	// Proxy trust (default: false — safe for direct exposure; set true behind reverse proxy)
	v.SetDefault("trust_proxy", false)

	// Dev mode (default: false — cookies set with Secure flag)
	v.SetDefault("dev_mode", false)

	// Datadog defaults
	v.SetDefault("datadog.agent_host", "localhost:4318")
	v.SetDefault("datadog.environment", "dev")
	v.SetDefault("datadog.service_name", "koopa")
}

// bindEnvVariables binds sensitive environment variables explicitly on the given viper instance.
// Only 3 environment variables for secrets:
//  1. GEMINI_API_KEY - Read directly by Genkit (not via Viper), validated in cfg.Validate()
//  2. DD_API_KEY - Datadog API key (optional, for observability)
//  3. HMAC_SECRET - HMAC secret for CSRF protection (serve mode only)
func bindEnvVariables(v *viper.Viper) {
	// Helper to panic on unexpected bind errors (hardcoded strings can't fail)
	// If this panics, it's a BUG in our code, not a runtime error
	mustBind := func(key, envVar string) {
		if err := v.BindEnv(key, envVar); err != nil {
			panic(fmt.Sprintf("BUG: failed to bind %q to %q: %v", key, envVar, err))
		}
	}

	// Datadog API key (optional, for observability)
	mustBind("datadog.api_key", "DD_API_KEY")

	// HMAC secret (serve mode CSRF protection)
	mustBind("hmac_secret", "HMAC_SECRET")

	// CORS origins (serve mode, comma-separated list)
	mustBind("cors_origins", "KOOPA_CORS_ORIGINS")

	// Proxy trust (serve mode, behind reverse proxy)
	mustBind("trust_proxy", "KOOPA_TRUST_PROXY")

	// Dev mode (serve mode, disables Secure cookie flag)
	mustBind("dev_mode", "KOOPA_DEV_MODE")

	// Data lifecycle
	mustBind("retention_days", "KOOPA_RETENTION_DAYS")

	// AI provider and model overrides
	mustBind("provider", "KOOPA_PROVIDER")
	mustBind("model_name", "KOOPA_MODEL_NAME")
	mustBind("ollama_host", "KOOPA_OLLAMA_HOST")

	// NOTE: GEMINI_API_KEY is read directly by Genkit, not via Viper
	// NOTE: OPENAI_API_KEY is read directly by Genkit OpenAI plugin, not via Viper
	// Validation checks their presence based on the selected provider in cfg.Validate()
}

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
//
// When adding new sensitive fields, update this method or the nested struct's MarshalJSON.
// The compiler will remind you when tests fail.
func (c Config) MarshalJSON() ([]byte, error) {
	type alias Config
	a := alias(c)
	a.PostgresPassword = maskSecret(a.PostgresPassword)
	a.HMACSecret = maskSecret(a.HMACSecret)
	// Note: Datadog.APIKey is handled by its own MarshalJSON
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return data, nil
}

// FullModelName returns the provider-qualified model name for Genkit.
// Examples: "googleai/gemini-2.5-flash", "ollama/llama3.3", "openai/gpt-4o".
// If ModelName already contains a "/", it is returned as-is.
func (c *Config) FullModelName() string {
	if strings.Contains(c.ModelName, "/") {
		return c.ModelName
	}
	switch c.Provider {
	case ProviderOllama:
		return ProviderOllama + "/" + c.ModelName
	case ProviderOpenAI:
		return ProviderOpenAI + "/" + c.ModelName
	default:
		return ProviderGoogleAI + "/" + c.ModelName
	}
}

// String implements Stringer to prevent accidental printing of secrets.
func (c Config) String() string {
	data, err := c.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("Config{error: %v}", err)
	}
	return string(data)
}
