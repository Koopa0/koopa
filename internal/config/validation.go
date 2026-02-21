package config

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/koopa0/koopa/internal/rag"
)

// supportedProviders lists all valid AI provider values.
var supportedProviders = []string{ProviderGemini, ProviderOllama, ProviderOpenAI}

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
	if err := c.validateRetention(); err != nil {
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
	if c.resolvedProvider() == ProviderOllama && c.OllamaHost == "" {
		return fmt.Errorf("%w: ollama_host cannot be empty when provider is ollama", ErrInvalidOllamaHost)
	}

	// RAG embedder
	if c.EmbedderModel == "" {
		return fmt.Errorf("%w: embedder_model cannot be empty", ErrInvalidEmbedderModel)
	}
	if err := c.validateEmbedder(); err != nil {
		return err
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
		return fmt.Errorf("%w: %q is not valid, must be one of: %v (allow/prefer excluded: MITM vulnerable)",
			ErrInvalidPostgresSSLMode, c.PostgresSSLMode, validSSLModes)
	}
	return nil
}

// knownEmbedderDimensions maps provider → model → native output dimension.
// Used to catch dimension mismatches at startup before hitting pgvector errors.
var knownEmbedderDimensions = map[string]map[string]int{
	ProviderGemini: {
		"gemini-embedding-001": 3072,
		"text-embedding-004":   768,
	},
	ProviderOpenAI: {
		"text-embedding-3-small": 1536,
		"text-embedding-3-large": 3072,
	},
}

// requiredVectorDimension must match the pgvector schema: embedding vector(768).
// Canonical source: rag.VectorDimension.
var requiredVectorDimension = int(rag.VectorDimension)

// validateEmbedder checks that the configured embedder model produces vectors
// compatible with the database schema. For known models whose native dimension
// differs from requiredVectorDimension, this returns an error so operators
// know to set OutputDimensionality (handled by rag.NewDocStoreConfig).
//
// Unknown providers or models pass validation silently — the operator may
// know what they are doing (e.g., a custom Ollama embedder producing 768-dim).
func (c *Config) validateEmbedder() error {
	models, ok := knownEmbedderDimensions[c.resolvedProvider()]
	if !ok {
		return nil // unknown provider (e.g., ollama) — skip
	}
	dim, ok := models[c.EmbedderModel]
	if !ok {
		return nil // unknown model — skip
	}
	if dim != requiredVectorDimension {
		slog.Warn("embedder native dimension differs from schema",
			"model", c.EmbedderModel,
			"native_dim", dim,
			"schema_dim", requiredVectorDimension,
			"note", "rag.NewDocStoreConfig truncates output via OutputDimensionality")
	}
	return nil
}

// resolvedProvider returns the effective provider, defaulting to "gemini".
func (c *Config) resolvedProvider() string {
	if c.Provider == "" {
		return ProviderGemini
	}
	return c.Provider
}

// ValidateServe validates configuration specific to serve mode.
// Serve mode is network-facing: default credentials and missing HMAC are hard errors.
func (c *Config) ValidateServe() error {
	if err := c.Validate(); err != nil {
		return err
	}
	// Block default development password in serve mode (network-facing).
	// The same password passes Validate() with a warning for CLI/MCP modes.
	if c.PostgresPassword == "koopa_dev_password" {
		return fmt.Errorf("%w: postgres_password must be changed from the default for serve mode",
			ErrDefaultPassword)
	}
	if c.HMACSecret == "" {
		return fmt.Errorf("%w: HMAC_SECRET environment variable is required for serve mode (min 32 characters)",
			ErrMissingHMACSecret)
	}
	if len(c.HMACSecret) < 32 {
		return fmt.Errorf("%w: must be at least 32 characters, got %d",
			ErrInvalidHMACSecret, len(c.HMACSecret))
	}
	if c.TrustProxy {
		slog.Warn("trust_proxy is enabled — ensure this server is behind a reverse proxy")
	}
	return nil
}

// validateRetention validates data lifecycle configuration.
func (c *Config) validateRetention() error {
	// 0 means disabled (no cleanup). Otherwise must be in [30, 3650].
	if c.RetentionDays != 0 && (c.RetentionDays < 30 || c.RetentionDays > 3650) {
		return fmt.Errorf("%w: must be 0 (disabled) or between 30 and 3650, got %d",
			ErrInvalidRetentionDays, c.RetentionDays)
	}
	return nil
}

// validateProviderAPIKey checks that the required API key is set for the configured provider.
// API keys are captured from environment in Load() and stored as unexported fields.
func (c *Config) validateProviderAPIKey() error {
	switch c.resolvedProvider() {
	case ProviderGemini:
		if c.geminiAPIKey == "" {
			return fmt.Errorf("%w: GEMINI_API_KEY environment variable is required for provider %q\n"+
				"Get your API key at: https://ai.google.dev/gemini-api/docs/api-key",
				ErrMissingAPIKey, c.resolvedProvider())
		}
	case ProviderOpenAI:
		if c.openaiAPIKey == "" {
			return fmt.Errorf("%w: OPENAI_API_KEY environment variable is required for provider %q\n"+
				"Get your API key at: https://platform.openai.com/api-keys",
				ErrMissingAPIKey, c.resolvedProvider())
		}
	case ProviderOllama:
		// Ollama runs locally, no API key required
	}
	return nil
}
