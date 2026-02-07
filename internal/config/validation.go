package config

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
)

// supportedProviders lists all valid AI provider values.
var supportedProviders = []string{"gemini", "ollama", "openai"}

// Validate validates configuration values.
// Returns sentinel errors that can be checked with errors.Is().
func (c *Config) Validate() error {
	if c == nil {
		return ErrConfigNil
	}

	if err := c.validateAI(); err != nil {
		return err
	}
	if err := c.validatePostgres(); err != nil {
		return err
	}
	return nil
}

// validateAI validates AI provider, model, and RAG configuration.
func (c *Config) validateAI() error {
	// Provider validation
	if c.Provider != "" && !slices.Contains(supportedProviders, c.Provider) {
		return fmt.Errorf("%w: %q (supported: %v)", ErrInvalidProvider, c.Provider, supportedProviders)
	}

	// Provider-specific API key
	if err := c.validateProviderAPIKey(); err != nil {
		return err
	}

	// Model name
	if c.ModelName == "" {
		return fmt.Errorf("%w: model_name cannot be empty", ErrInvalidModelName)
	}

	// Temperature: 0.0 (deterministic) to 2.0 (maximum creativity)
	if c.Temperature < 0.0 || c.Temperature > 2.0 {
		return fmt.Errorf("%w: must be between 0.0 and 2.0, got %.2f", ErrInvalidTemperature, c.Temperature)
	}

	// MaxTokens: 1 to 2097152 (Gemini 2.5 max context window)
	if c.MaxTokens < 1 || c.MaxTokens > 2097152 {
		return fmt.Errorf("%w: must be between 1 and 2,097,152, got %d", ErrInvalidMaxTokens, c.MaxTokens)
	}

	// Ollama host
	if c.resolvedProvider() == "ollama" && c.OllamaHost == "" {
		return fmt.Errorf("%w: ollama_host cannot be empty when provider is ollama", ErrInvalidOllamaHost)
	}

	// RAG
	if c.RAGTopK <= 0 || c.RAGTopK > 10 {
		return fmt.Errorf("%w: must be between 1 and 10, got %d", ErrInvalidRAGTopK, c.RAGTopK)
	}
	if c.EmbedderModel == "" {
		return fmt.Errorf("%w: embedder_model cannot be empty", ErrInvalidEmbedderModel)
	}

	return nil
}

// validatePostgres validates PostgreSQL connection configuration.
func (c *Config) validatePostgres() error {
	if c.PostgresHost == "" {
		return fmt.Errorf("%w: host cannot be empty", ErrInvalidPostgresHost)
	}
	if c.PostgresPort < 1 || c.PostgresPort > 65535 {
		return fmt.Errorf("%w: must be between 1 and 65535, got %d", ErrInvalidPostgresPort, c.PostgresPort)
	}
	if c.PostgresDBName == "" {
		return fmt.Errorf("%w: database name cannot be empty", ErrInvalidPostgresDBName)
	}
	if c.PostgresPassword == "" {
		return fmt.Errorf("%w: postgres_password must be set in config.yaml",
			ErrInvalidPostgresPassword)
	}
	if c.PostgresPassword == "koopa_dev_password" {
		slog.Warn("Using default development password for PostgreSQL",
			"warning", "Change postgres_password in config.yaml for production deployments")
	}
	if len(c.PostgresPassword) < 8 {
		return fmt.Errorf("%w: postgres_password must be at least 8 characters (got %d)",
			ErrInvalidPostgresPassword, len(c.PostgresPassword))
	}
	return c.validatePostgresSSL()
}

// validatePostgresSSL validates the PostgreSQL SSL mode.
func (c *Config) validatePostgresSSL() error {
	// Modern SSL modes only - exclude deprecated allow/prefer (MITM vulnerable)
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if c.PostgresSSLMode == "" {
		return fmt.Errorf("%w: postgres_ssl_mode is empty (should have default from setDefaults)",
			ErrInvalidPostgresSSLMode)
	}
	if !slices.Contains(validSSLModes, c.PostgresSSLMode) {
		return fmt.Errorf("%w: %q is not valid, must be one of: %v\n"+
			"Note: 'allow' and 'prefer' modes are deprecated (vulnerable to MITM attacks)",
			ErrInvalidPostgresSSLMode, c.PostgresSSLMode, validSSLModes)
	}
	return nil
}

// resolvedProvider returns the effective provider, defaulting to "gemini".
func (c *Config) resolvedProvider() string {
	if c.Provider == "" {
		return "gemini"
	}
	return c.Provider
}

// validateProviderAPIKey checks that the required API key is set for the configured provider.
func (c *Config) validateProviderAPIKey() error {
	switch c.resolvedProvider() {
	case "gemini":
		if os.Getenv("GEMINI_API_KEY") == "" {
			return fmt.Errorf("%w: GEMINI_API_KEY environment variable is required for provider %q\n"+
				"Get your API key at: https://ai.google.dev/gemini-api/docs/api-key",
				ErrMissingAPIKey, c.resolvedProvider())
		}
	case "openai":
		if os.Getenv("OPENAI_API_KEY") == "" {
			return fmt.Errorf("%w: OPENAI_API_KEY environment variable is required for provider %q\n"+
				"Get your API key at: https://platform.openai.com/api-keys",
				ErrMissingAPIKey, c.resolvedProvider())
		}
	case "ollama":
		// Ollama runs locally, no API key required
	}
	return nil
}
