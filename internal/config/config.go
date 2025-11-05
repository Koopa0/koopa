package config

import (
	"fmt"
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
	VectorPath   string `mapstructure:"vector_path"`   // Vector database (chromem-go) path

	// RAG (Retrieval-Augmented Generation) configuration
	RAGTopK       int    `mapstructure:"rag_top_k"`      // Number of documents to retrieve for RAG (default: 3)
	EmbedderModel string `mapstructure:"embedder_model"` // Embedding model name

	// API Keys
	GeminiAPIKey string `mapstructure:"gemini_api_key"`
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
	if err := os.MkdirAll(configDir, 0750); err != nil {
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
	viper.SetDefault("vector_path", filepath.Join(configDir, "chromem"))
	viper.SetDefault("rag_top_k", 3)                         // Default: retrieve top 3 documents
	viper.SetDefault("embedder_model", "text-embedding-004") // Default Google AI embedder

	// Read configuration file (if exists)
	if err := viper.ReadInConfig(); err != nil {
		// Configuration file not found is not an error, use default values
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	// Environment variable settings (using KOOPA_ prefix)
	// Explicitly bind each configuration key to corresponding environment variable
	viper.SetEnvPrefix("KOOPA")
	_ = viper.BindEnv("model_name")
	_ = viper.BindEnv("temperature")
	_ = viper.BindEnv("max_tokens")
	_ = viper.BindEnv("max_history_messages")
	_ = viper.BindEnv("database_path")
	_ = viper.BindEnv("vector_path")
	_ = viper.BindEnv("rag_top_k")
	_ = viper.BindEnv("embedder_model")
	_ = viper.BindEnv("gemini_api_key")

	// Use Unmarshal to automatically map to struct (type-safe)
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &cfg, nil
}

// GetPlugins returns Genkit plugins
func (c *Config) GetPlugins() []any {
	return []any{&googlegenai.GoogleAI{}}
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.GeminiAPIKey == "" {
		return &ConfigError{
			Field:   "GEMINI_API_KEY",
			Message: "Gemini API key is required. Set GEMINI_API_KEY environment variable or add it to config file.",
		}
	}

	// Validate RAG configuration
	if c.RAGTopK <= 0 {
		c.RAGTopK = 3 // Default to 3 if invalid
	}
	if c.RAGTopK > 10 {
		c.RAGTopK = 10 // Cap at 10 to avoid token overflow
	}

	if c.EmbedderModel == "" {
		c.EmbedderModel = "text-embedding-004" // Default embedder
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
