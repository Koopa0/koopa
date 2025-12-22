package config

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
)

// Validate validates configuration values.
// Returns sentinel errors that can be checked with errors.Is().
func (c *Config) Validate() error {
	// 0. Check for nil config (defensive programming)
	if c == nil {
		return ErrConfigNil
	}

	// 1. API Key validation (required for all AI operations)
	if os.Getenv("GEMINI_API_KEY") == "" {
		return fmt.Errorf("%w: GEMINI_API_KEY environment variable is required\n"+
			"Get your API key at: https://ai.google.dev/gemini-api/docs/api-key",
			ErrMissingAPIKey)
	}

	// 2. Model configuration validation
	if c.ModelName == "" {
		return fmt.Errorf("%w: model_name cannot be empty", ErrInvalidModelName)
	}

	// Temperature range: 0.0 (deterministic) to 2.0 (maximum creativity)
	// Reference: Gemini API documentation
	if c.Temperature < 0.0 || c.Temperature > 2.0 {
		return fmt.Errorf("%w: must be between 0.0 and 2.0, got %.2f", ErrInvalidTemperature, c.Temperature)
	}

	// MaxTokens range: 1 to 2097152 (Gemini 2.5 max context window)
	// Reference: https://ai.google.dev/gemini-api/docs/models
	if c.MaxTokens < 1 || c.MaxTokens > 2097152 {
		return fmt.Errorf("%w: must be between 1 and 2,097,152, got %d", ErrInvalidMaxTokens, c.MaxTokens)
	}

	// 3. RAG configuration validation
	if c.RAGTopK <= 0 || c.RAGTopK > 10 {
		return fmt.Errorf("%w: must be between 1 and 10, got %d", ErrInvalidRAGTopK, c.RAGTopK)
	}

	if c.EmbedderModel == "" {
		return fmt.Errorf("%w: embedder_model cannot be empty", ErrInvalidEmbedderModel)
	}

	// 4. PostgreSQL configuration validation
	if c.PostgresHost == "" {
		return fmt.Errorf("%w: host cannot be empty", ErrInvalidPostgresHost)
	}

	if c.PostgresPort < 1 || c.PostgresPort > 65535 {
		return fmt.Errorf("%w: must be between 1 and 65535, got %d", ErrInvalidPostgresPort, c.PostgresPort)
	}

	if c.PostgresDBName == "" {
		return fmt.Errorf("%w: database name cannot be empty", ErrInvalidPostgresDBName)
	}

	// 4. PostgreSQL password validation
	if c.PostgresPassword == "" {
		return fmt.Errorf("%w: postgres_password must be set in config.yaml",
			ErrInvalidPostgresPassword)
	}

	// CRITICAL: Warn if using default dev password (but don't block - user might be in dev)
	if c.PostgresPassword == "koopa_dev_password" {
		slog.Warn("Using default development password for PostgreSQL",
			"warning", "Change postgres_password in config.yaml for production deployments")
	}

	// Validate password strength (minimum 8 characters)
	if len(c.PostgresPassword) < 8 {
		return fmt.Errorf("%w: postgres_password must be at least 8 characters (got %d)",
			ErrInvalidPostgresPassword, len(c.PostgresPassword))
	}

	// 5. PostgreSQL SSL mode validation
	// DO NOT mutate config in Validate() - just validate
	// Note: Even with setDefaults(), user can override with empty value in YAML
	// Modern SSL modes only - exclude deprecated allow/prefer (MITM vulnerable)
	// Reference: https://www.postgresql.org/docs/current/libpq-ssl.html
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if c.PostgresSSLMode == "" {
		return fmt.Errorf("%w: postgres_ssl_mode is empty (should have default from setDefaults)",
			ErrInvalidPostgresSSLMode)
	}

	// Check if SSL mode is one of the valid PostgreSQL modes
	if !slices.Contains(validSSLModes, c.PostgresSSLMode) {
		return fmt.Errorf("%w: %q is not valid, must be one of: %v\n"+
			"Note: 'allow' and 'prefer' modes are deprecated (vulnerable to MITM attacks)",
			ErrInvalidPostgresSSLMode, c.PostgresSSLMode, validSSLModes)
	}

	return nil
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
