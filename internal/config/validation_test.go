package config

import (
	"errors"
	"strings"
	"testing"
)

// validBaseConfig returns a Config with all required fields set for the given provider.
func validBaseConfig(provider string) *Config {
	cfg := &Config{
		Provider:         provider,
		ModelName:        "gemini-2.5-flash",
		Temperature:      0.7,
		MaxTokens:        2048,
		EmbedderModel:    "gemini-embedding-001",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresPassword: "test_password",
		PostgresDBName:   "koopa",
		PostgresSSLMode:  "disable",
	}
	switch provider {
	case "ollama":
		cfg.ModelName = "llama3.3"
		cfg.OllamaHost = "http://localhost:11434"
	case "openai":
		cfg.ModelName = "gpt-4o"
		cfg.openaiAPIKey = "test-openai-key"
	default:
		// gemini is the default provider (including when provider is "")
		cfg.geminiAPIKey = "test-gemini-key"
	}
	return cfg
}

// TestValidateSuccess tests successful validation for each provider.
func TestValidateSuccess(t *testing.T) {
	providers := []string{"", "gemini", "ollama", "openai"}

	for _, provider := range providers {
		name := provider
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			cfg := validBaseConfig(provider)
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() unexpected error with valid config (provider %q): %v", provider, err)
			}
		})
	}
}

// TestValidateInvalidProvider tests that unsupported providers are rejected.
func TestValidateInvalidProvider(t *testing.T) {
	cfg := validBaseConfig("")
	cfg.Provider = "unsupported"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported provider, got nil")
	}
	if !errors.Is(err, ErrInvalidProvider) {
		t.Errorf("Validate() error = %v, want ErrInvalidProvider", err)
	}
}

// TestValidateProviderAPIKey tests provider-specific API key validation.
func TestValidateProviderAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{name: "gemini missing key", provider: "gemini", wantErr: true},
		{name: "openai missing key", provider: "openai", wantErr: true},
		{name: "ollama no key needed", provider: "ollama", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig(tt.provider)
			// Clear API keys to test missing key scenario
			cfg.geminiAPIKey = ""
			cfg.openaiAPIKey = ""

			err := cfg.Validate()

			if tt.wantErr && err == nil {
				t.Errorf("expected error for missing API key (provider %q), got nil", tt.provider)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for provider %q: %v", tt.provider, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrMissingAPIKey) {
				t.Errorf("error should be ErrMissingAPIKey, got: %v", err)
			}
		})
	}
}

// TestValidateModelName tests model name validation.
func TestValidateModelName(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.ModelName = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty model name, got nil")
	}
	if !errors.Is(err, ErrInvalidModelName) {
		t.Errorf("error should be ErrInvalidModelName, got: %v", err)
	}
}

// TestValidateTemperature tests temperature range validation.
func TestValidateTemperature(t *testing.T) {
	tests := []struct {
		name        string
		temperature float32
		wantErr     bool
	}{
		{name: "valid min", temperature: 0.0},
		{name: "valid mid", temperature: 1.0},
		{name: "valid max", temperature: 2.0},
		{name: "invalid negative", temperature: -0.1, wantErr: true},
		{name: "invalid too high", temperature: 2.1, wantErr: true},
		{name: "invalid far negative", temperature: -5.0, wantErr: true},
		{name: "invalid far too high", temperature: 10.0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.Temperature = tt.temperature

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for temperature %.2f, got nil", tt.temperature)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for temperature %.2f: %v", tt.temperature, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidTemperature) {
				t.Errorf("error should be ErrInvalidTemperature, got: %v", err)
			}
		})
	}
}

// TestValidateMaxTokens tests max tokens range validation.
func TestValidateMaxTokens(t *testing.T) {
	tests := []struct {
		name      string
		maxTokens int
		wantErr   bool
	}{
		{name: "valid min", maxTokens: 1},
		{name: "valid mid", maxTokens: 100000},
		{name: "valid max", maxTokens: 2097152},
		{name: "invalid zero", maxTokens: 0, wantErr: true},
		{name: "invalid negative", maxTokens: -1, wantErr: true},
		{name: "invalid too high", maxTokens: 2097153, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.MaxTokens = tt.maxTokens

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for max_tokens %d, got nil", tt.maxTokens)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for max_tokens %d: %v", tt.maxTokens, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidMaxTokens) {
				t.Errorf("error should be ErrInvalidMaxTokens, got: %v", err)
			}
		})
	}
}

// TestValidateOllamaHost tests Ollama host validation.
func TestValidateOllamaHost(t *testing.T) {
	cfg := validBaseConfig("ollama")
	cfg.OllamaHost = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty ollama_host, got nil")
	}
	if !errors.Is(err, ErrInvalidOllamaHost) {
		t.Errorf("error should be ErrInvalidOllamaHost, got: %v", err)
	}
}

// TestValidateEmbedderModel tests embedder model validation.
func TestValidateEmbedderModel(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.EmbedderModel = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty embedder_model, got nil")
	}
	if !errors.Is(err, ErrInvalidEmbedderModel) {
		t.Errorf("Validate() error = %v, want ErrInvalidEmbedderModel", err)
	}
}

// TestValidatePostgresHost tests PostgreSQL host validation.
func TestValidatePostgresHost(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.PostgresHost = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty postgres_host, got nil")
	}
	if !errors.Is(err, ErrInvalidPostgresHost) {
		t.Errorf("error should be ErrInvalidPostgresHost, got: %v", err)
	}
}

// TestValidatePostgresPort tests PostgreSQL port validation.
func TestValidatePostgresPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "valid min", port: 1},
		{name: "valid standard", port: 5432},
		{name: "valid max", port: 65535},
		{name: "invalid zero", port: 0, wantErr: true},
		{name: "invalid negative", port: -1, wantErr: true},
		{name: "invalid too high", port: 65536, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.PostgresPort = tt.port

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for port %d, got nil", tt.port)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for port %d: %v", tt.port, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidPostgresPort) {
				t.Errorf("error should be ErrInvalidPostgresPort, got: %v", err)
			}
		})
	}
}

// TestValidatePostgresDBName tests PostgreSQL database name validation.
func TestValidatePostgresDBName(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.PostgresDBName = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty postgres_db_name, got nil")
	}
	if !errors.Is(err, ErrInvalidPostgresDBName) {
		t.Errorf("error should be ErrInvalidPostgresDBName, got: %v", err)
	}
}

// TestValidatePostgresPassword tests PostgreSQL password validation.
func TestValidatePostgresPassword(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantErr   bool
		errSubstr string
	}{
		{name: "valid password", password: "securepass123"},
		{name: "valid long password", password: "very_secure_password_with_many_chars"},
		{name: "empty password", password: "", wantErr: true, errSubstr: "must be set"},
		{name: "too short 1 char", password: "a", wantErr: true, errSubstr: "at least 8 characters"},
		{name: "too short 7 chars", password: "1234567", wantErr: true, errSubstr: "at least 8 characters"},
		{name: "exactly 8 chars", password: "12345678"},
		{name: "default dev password", password: "koopa_dev_password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.PostgresPassword = tt.password

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for password %q, got nil", tt.password)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for password %q: %v", tt.password, err)
			}
			if tt.wantErr && err != nil {
				if !errors.Is(err, ErrInvalidPostgresPassword) {
					t.Errorf("error should be ErrInvalidPostgresPassword, got: %v", err)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error should contain %q, got: %v", tt.errSubstr, err)
				}
			}
		})
	}
}

// TestValidatePostgresSSLMode tests PostgreSQL SSL mode validation.
func TestValidatePostgresSSLMode(t *testing.T) {
	tests := []struct {
		name    string
		sslMode string
		wantErr bool
	}{
		{name: "valid disable", sslMode: "disable"},
		{name: "valid require", sslMode: "require"},
		{name: "valid verify-ca", sslMode: "verify-ca"},
		{name: "valid verify-full", sslMode: "verify-full"},
		{name: "invalid empty", sslMode: "", wantErr: true},
		{name: "invalid mode", sslMode: "invalid", wantErr: true},
		{name: "typo disabled", sslMode: "disabled", wantErr: true},
		{name: "deprecated allow", sslMode: "allow", wantErr: true},
		{name: "deprecated prefer", sslMode: "prefer", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.PostgresSSLMode = tt.sslMode

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for SSL mode %q, got nil", tt.sslMode)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for SSL mode %q: %v", tt.sslMode, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidPostgresSSLMode) {
				t.Errorf("error should be ErrInvalidPostgresSSLMode, got: %v", err)
			}
		})
	}
}

// TestValidateServe_DefaultPassword verifies that ValidateServe rejects the
// default development password (koopa_dev_password) as a hard error.
// The same password passes Validate() with only a warning for CLI/MCP modes.
func TestValidateServe_DefaultPassword(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.PostgresPassword = "koopa_dev_password"
	cfg.HMACSecret = "test-hmac-secret-that-is-at-least-32-characters-long"

	err := cfg.ValidateServe()
	if err == nil {
		t.Fatal("ValidateServe() with default password error = nil, want ErrDefaultPassword")
	}
	if !errors.Is(err, ErrDefaultPassword) {
		t.Errorf("ValidateServe() error = %v, want ErrDefaultPassword", err)
	}

	// Confirm the same config passes Validate() (non-serve mode allows default password with warning).
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with default password unexpected error: %v", err)
	}
}

// TestValidateServe_NonDefaultPassword verifies that ValidateServe succeeds
// when the password is not the default value.
func TestValidateServe_NonDefaultPassword(t *testing.T) {
	cfg := validBaseConfig("gemini")
	cfg.PostgresPassword = "production_secure_password"
	cfg.HMACSecret = "test-hmac-secret-that-is-at-least-32-characters-long"

	if err := cfg.ValidateServe(); err != nil {
		t.Errorf("ValidateServe() with non-default password unexpected error: %v", err)
	}
}

// TestValidateRetentionDays tests retention days range validation.
func TestValidateRetentionDays(t *testing.T) {
	tests := []struct {
		name          string
		retentionDays int
		wantErr       bool
	}{
		{name: "disabled (zero)", retentionDays: 0},
		{name: "valid min", retentionDays: 30},
		{name: "valid mid", retentionDays: 365},
		{name: "valid max", retentionDays: 3650},
		{name: "invalid below min", retentionDays: 29, wantErr: true},
		{name: "invalid one", retentionDays: 1, wantErr: true},
		{name: "invalid above max", retentionDays: 3651, wantErr: true},
		{name: "invalid negative", retentionDays: -1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig("gemini")
			cfg.RetentionDays = tt.retentionDays

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() with RetentionDays=%d: expected error, got nil", tt.retentionDays)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() with RetentionDays=%d: unexpected error: %v", tt.retentionDays, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidRetentionDays) {
				t.Errorf("Validate() with RetentionDays=%d: error = %v, want ErrInvalidRetentionDays", tt.retentionDays, err)
			}
		})
	}
}

// BenchmarkValidate benchmarks configuration validation.
func BenchmarkValidate(b *testing.B) {
	cfg := validBaseConfig("gemini")

	if err := cfg.Validate(); err != nil {
		b.Fatalf("Validate() unexpected error: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = cfg.Validate()
	}
}
