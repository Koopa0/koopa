package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestValidateSuccess tests successful validation
func TestValidateSuccess(t *testing.T) {
	originalAPIKey := os.Getenv("GEMINI_API_KEY")
	defer func() {
		if originalAPIKey != "" {
			if err := os.Setenv("GEMINI_API_KEY", originalAPIKey); err != nil {
				t.Errorf("Failed to restore GEMINI_API_KEY: %v", err)
			}
		} else {
			if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
				t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
			}
		}
	}()

	if err := os.Setenv("GEMINI_API_KEY", "test-api-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}

	cfg := &Config{
		ModelName:        "gemini-2.5-flash",
		Temperature:      0.7,
		MaxTokens:        2048,
		RAGTopK:          3,
		EmbedderModel:    "text-embedding-004",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresPassword: "test_password",
		PostgresDBName:   "koopa",
		PostgresSSLMode:  "disable",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() failed with valid config: %v", err)
	}
}

// TestValidateMissingAPIKey tests validation failure when API key is missing
func TestValidateMissingAPIKey(t *testing.T) {
	originalAPIKey := os.Getenv("GEMINI_API_KEY")
	defer func() {
		if originalAPIKey != "" {
			if err := os.Setenv("GEMINI_API_KEY", originalAPIKey); err != nil {
				t.Errorf("Failed to restore GEMINI_API_KEY: %v", err)
			}
		} else {
			if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
				t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
			}
		}
	}()

	if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
		t.Fatalf("Failed to unset GEMINI_API_KEY: %v", err)
	}

	cfg := &Config{
		ModelName:      "gemini-2.5-flash",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "localhost",
		PostgresPort:   5432,
		PostgresDBName: "koopa",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing API key, got none")
	}

	if !strings.Contains(err.Error(), "GEMINI_API_KEY") {
		t.Errorf("error should mention GEMINI_API_KEY, got: %v", err)
	}
}

// TestValidateModelName tests model name validation
func TestValidateModelName(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	cfg := &Config{
		ModelName:      "",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "localhost",
		PostgresPort:   5432,
		PostgresDBName: "koopa",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for empty model name, got none")
	}

	if !strings.Contains(err.Error(), "model_name") {
		t.Errorf("error should mention model_name, got: %v", err)
	}
}

// TestValidateTemperature tests temperature range validation
func TestValidateTemperature(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	tests := []struct {
		name        string
		temperature float32
		shouldErr   bool
	}{
		{"valid min", 0.0, false},
		{"valid mid", 1.0, false},
		{"valid max", 2.0, false},
		{"invalid negative", -0.1, true},
		{"invalid too high", 2.1, true},
		{"invalid far negative", -5.0, true},
		{"invalid far too high", 10.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      tt.temperature,
				MaxTokens:        2048,
				RAGTopK:          3,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresPassword: "test_password",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for temperature %f, got none", tt.temperature)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for temperature %f: %v", tt.temperature, err)
			}
			if tt.shouldErr && err != nil && !errors.Is(err, ErrInvalidTemperature) {
				t.Errorf("error should be ErrInvalidTemperature, got: %v", err)
			}
		})
	}
}

// TestValidateMaxTokens tests max tokens range validation
func TestValidateMaxTokens(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	tests := []struct {
		name      string
		maxTokens int
		shouldErr bool
	}{
		{"valid min", 1, false},
		{"valid mid", 100000, false},
		{"valid max", 2097152, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 2097153, true},
		{"invalid far too high", 10000000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      0.7,
				MaxTokens:        tt.maxTokens,
				RAGTopK:          3,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresPassword: "test_password",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for max_tokens %d, got none", tt.maxTokens)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for max_tokens %d: %v", tt.maxTokens, err)
			}
			if tt.shouldErr && err != nil && !errors.Is(err, ErrInvalidMaxTokens) {
				t.Errorf("error should be ErrInvalidMaxTokens, got: %v", err)
			}
		})
	}
}

// TestValidateRAGTopK tests RAG top K validation
func TestValidateRAGTopK(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	tests := []struct {
		name      string
		ragTopK   int
		shouldErr bool
	}{
		{"valid min", 1, false},
		{"valid mid", 5, false},
		{"valid max", 10, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 11, true},
		{"invalid far too high", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      0.7,
				MaxTokens:        2048,
				RAGTopK:          tt.ragTopK,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresPassword: "test_password",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for rag_top_k %d, got none", tt.ragTopK)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for rag_top_k %d: %v", tt.ragTopK, err)
			}
			if tt.shouldErr && err != nil && !errors.Is(err, ErrInvalidRAGTopK) {
				t.Errorf("error should be ErrInvalidRAGTopK, got: %v", err)
			}
		})
	}
}

// TestValidateEmbedderModel tests embedder model validation
func TestValidateEmbedderModel(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	cfg := &Config{
		ModelName:      "gemini-2.5-flash",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "",
		PostgresHost:   "localhost",
		PostgresPort:   5432,
		PostgresDBName: "koopa",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for empty embedder_model, got none")
	}

	if !strings.Contains(err.Error(), "embedder_model") {
		t.Errorf("error should mention embedder_model, got: %v", err)
	}
}

// TestValidatePostgresHost tests PostgreSQL host validation
func TestValidatePostgresHost(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	cfg := &Config{
		ModelName:      "gemini-2.5-flash",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "",
		PostgresPort:   5432,
		PostgresDBName: "koopa",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for empty postgres_host, got none")
	}

	if !strings.Contains(err.Error(), "PostgreSQL host") {
		t.Errorf("error should mention PostgreSQL host, got: %v", err)
	}
}

// TestValidatePostgresPort tests PostgreSQL port validation
func TestValidatePostgresPort(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	tests := []struct {
		name      string
		port      int
		shouldErr bool
	}{
		{"valid min", 1, false},
		{"valid standard", 5432, false},
		{"valid max", 65535, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 65536, true},
		{"invalid far too high", 100000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      0.7,
				MaxTokens:        2048,
				RAGTopK:          3,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     tt.port,
				PostgresPassword: "test_password",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for postgres_port %d, got none", tt.port)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for postgres_port %d: %v", tt.port, err)
			}
			if tt.shouldErr && err != nil && !strings.Contains(err.Error(), "PostgreSQL port") {
				t.Errorf("error should mention PostgreSQL port, got: %v", err)
			}
		})
	}
}

// TestValidatePostgresDBName tests PostgreSQL database name validation
func TestValidatePostgresDBName(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	cfg := &Config{
		ModelName:      "gemini-2.5-flash",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "localhost",
		PostgresPort:   5432,
		PostgresDBName: "",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for empty postgres_db_name, got none")
	}

	if !strings.Contains(err.Error(), "database name") {
		t.Errorf("error should mention database name, got: %v", err)
	}
}

// TestNormalizeMaxHistoryMessages tests max history messages normalization
func TestNormalizeMaxHistoryMessages(t *testing.T) {
	tests := []struct {
		name  string
		input int32
		want  int32
	}{
		{"zero returns default", 0, DefaultMaxHistoryMessages},
		{"negative returns default", -10, DefaultMaxHistoryMessages},
		{"below min returns min", MinHistoryMessages - 1, MinHistoryMessages},
		{"at min", MinHistoryMessages, MinHistoryMessages},
		{"normal value", 500, 500},
		{"at max", MaxAllowedHistoryMessages, MaxAllowedHistoryMessages},
		{"above max returns max", MaxAllowedHistoryMessages + 1, MaxAllowedHistoryMessages},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeMaxHistoryMessages(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeMaxHistoryMessages(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// BenchmarkValidate benchmarks configuration validation
func BenchmarkValidate(b *testing.B) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		b.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			b.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	cfg := &Config{
		ModelName:        "gemini-2.5-flash",
		Temperature:      0.7,
		MaxTokens:        2048,
		RAGTopK:          3,
		EmbedderModel:    "text-embedding-004",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresDBName:   "koopa",
		PostgresPassword: "securepass123",
		PostgresSSLMode:  "disable",
	}

	// Verify Validate() works before starting benchmark
	if err := cfg.Validate(); err != nil {
		b.Fatalf("Validate() failed: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = cfg.Validate()
	}
}

// TestValidatePostgresPassword tests PostgreSQL password validation
func TestValidatePostgresPassword(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer os.Unsetenv("GEMINI_API_KEY")

	tests := []struct {
		name      string
		password  string
		shouldErr bool
		errSubstr string
	}{
		{"valid password", "securepass123", false, ""},
		{"valid long password", "very_secure_password_with_many_chars", false, ""},
		{"empty password", "", true, "must be set"},
		{"too short 1 char", "a", true, "at least 8 characters"},
		{"too short 7 chars", "1234567", true, "at least 8 characters"},
		{"exactly 8 chars", "12345678", false, ""},
		// Default password should be allowed but warns (tested separately)
		{"default dev password", "koopa_dev_password", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      0.7,
				MaxTokens:        2048,
				RAGTopK:          3,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresPassword: tt.password,
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for password %q, got none", tt.password)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for password %q: %v", tt.password, err)
			}
			if tt.shouldErr && err != nil {
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

// TestValidatePostgresSSLMode tests PostgreSQL SSL mode validation
func TestValidatePostgresSSLMode(t *testing.T) {
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer os.Unsetenv("GEMINI_API_KEY")

	tests := []struct {
		name      string
		sslMode   string
		shouldErr bool
	}{
		{"valid disable", "disable", false},
		{"valid require", "require", false},
		{"valid verify-ca", "verify-ca", false},
		{"valid verify-full", "verify-full", false},
		{"invalid empty", "", true},
		{"invalid mode", "invalid", true},
		{"typo disabled", "disabled", true}, // Common mistake
		{"typo enabled", "enabled", true},
		{"deprecated allow", "allow", true},   // No longer supported
		{"deprecated prefer", "prefer", true}, // No longer supported
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ModelName:        "gemini-2.5-flash",
				Temperature:      0.7,
				MaxTokens:        2048,
				RAGTopK:          3,
				EmbedderModel:    "text-embedding-004",
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresPassword: "test_password",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  tt.sslMode,
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for SSL mode %q, got none", tt.sslMode)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for SSL mode %q: %v", tt.sslMode, err)
			}
			if tt.shouldErr && err != nil && !errors.Is(err, ErrInvalidPostgresSSLMode) {
				t.Errorf("error should be ErrInvalidPostgresSSLMode, got: %v", err)
			}
		})
	}
}
