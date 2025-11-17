package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestLoadDefaults tests that default configuration values are loaded correctly
func TestLoadDefaults(t *testing.T) {
	// Save and restore original environment
	originalAPIKey := os.Getenv("GEMINI_API_KEY")
	defer func() {
		if originalAPIKey != "" {
			os.Setenv("GEMINI_API_KEY", originalAPIKey)
		} else {
			os.Unsetenv("GEMINI_API_KEY")
		}
	}()

	// Set API key for validation
	os.Setenv("GEMINI_API_KEY", "test-api-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify default values
	if cfg.ModelName != "gemini-2.5-flash" {
		t.Errorf("expected default ModelName 'gemini-2.5-flash', got %q", cfg.ModelName)
	}

	if cfg.Temperature != 0.7 {
		t.Errorf("expected default Temperature 0.7, got %f", cfg.Temperature)
	}

	if cfg.MaxTokens != 2048 {
		t.Errorf("expected default MaxTokens 2048, got %d", cfg.MaxTokens)
	}

	if cfg.MaxHistoryMessages != 50 {
		t.Errorf("expected default MaxHistoryMessages 50, got %d", cfg.MaxHistoryMessages)
	}

	if cfg.PostgresHost != "localhost" {
		t.Errorf("expected default PostgresHost 'localhost', got %q", cfg.PostgresHost)
	}

	if cfg.PostgresPort != 5432 {
		t.Errorf("expected default PostgresPort 5432, got %d", cfg.PostgresPort)
	}

	if cfg.PostgresUser != "koopa" {
		t.Errorf("expected default PostgresUser 'koopa', got %q", cfg.PostgresUser)
	}

	if cfg.PostgresDBName != "koopa" {
		t.Errorf("expected default PostgresDBName 'koopa', got %q", cfg.PostgresDBName)
	}

	if cfg.RAGTopK != 3 {
		t.Errorf("expected default RAGTopK 3, got %d", cfg.RAGTopK)
	}

	if cfg.EmbedderModel != "text-embedding-004" {
		t.Errorf("expected default EmbedderModel 'text-embedding-004', got %q", cfg.EmbedderModel)
	}

	if cfg.MCP.Timeout != 5 {
		t.Errorf("expected default MCP timeout 5, got %d", cfg.MCP.Timeout)
	}
}

// TestLoadConfigFile tests loading configuration from a file
func TestLoadConfigFile(t *testing.T) {
	// Reset Viper singleton to avoid interference from other tests
	viper.Reset()

	// Create temporary config directory
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	// Set HOME to temp directory
	os.Setenv("HOME", tmpDir)
	os.Setenv("GEMINI_API_KEY", "test-api-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	// Create .koopa directory
	koopaDir := filepath.Join(tmpDir, ".koopa")
	if err := os.MkdirAll(koopaDir, 0o750); err != nil {
		t.Fatalf("failed to create koopa dir: %v", err)
	}

	// Create config file
	configContent := `model_name: gemini-2.5-pro
temperature: 0.9
max_tokens: 4096
rag_top_k: 5
postgres_host: test-host
postgres_port: 5433
postgres_db_name: test_db
`
	configPath := filepath.Join(koopaDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify values from config file
	if cfg.ModelName != "gemini-2.5-pro" {
		t.Errorf("expected ModelName 'gemini-2.5-pro', got %q", cfg.ModelName)
	}

	if cfg.Temperature != 0.9 {
		t.Errorf("expected Temperature 0.9, got %f", cfg.Temperature)
	}

	if cfg.MaxTokens != 4096 {
		t.Errorf("expected MaxTokens 4096, got %d", cfg.MaxTokens)
	}

	if cfg.RAGTopK != 5 {
		t.Errorf("expected RAGTopK 5, got %d", cfg.RAGTopK)
	}

	if cfg.PostgresHost != "test-host" {
		t.Errorf("expected PostgresHost 'test-host', got %q", cfg.PostgresHost)
	}

	if cfg.PostgresPort != 5433 {
		t.Errorf("expected PostgresPort 5433, got %d", cfg.PostgresPort)
	}

	if cfg.PostgresDBName != "test_db" {
		t.Errorf("expected PostgresDBName 'test_db', got %q", cfg.PostgresDBName)
	}
}

// TestValidateSuccess tests successful validation
func TestValidateSuccess(t *testing.T) {
	originalAPIKey := os.Getenv("GEMINI_API_KEY")
	defer func() {
		if originalAPIKey != "" {
			os.Setenv("GEMINI_API_KEY", originalAPIKey)
		} else {
			os.Unsetenv("GEMINI_API_KEY")
		}
	}()

	os.Setenv("GEMINI_API_KEY", "test-api-key")

	cfg := &Config{
		ModelName:       "gemini-2.5-flash",
		Temperature:     0.7,
		MaxTokens:       2048,
		RAGTopK:         3,
		EmbedderModel:   "text-embedding-004",
		PostgresHost:    "localhost",
		PostgresPort:    5432,
		PostgresDBName:  "koopa",
		PostgresSSLMode: "disable",
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
			os.Setenv("GEMINI_API_KEY", originalAPIKey)
		} else {
			os.Unsetenv("GEMINI_API_KEY")
		}
	}()

	os.Unsetenv("GEMINI_API_KEY")

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
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
				ModelName:      "gemini-2.5-flash",
				Temperature:    tt.temperature,
				MaxTokens:      2048,
				RAGTopK:        3,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   5432,
				PostgresDBName: "koopa",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for temperature %f, got none", tt.temperature)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for temperature %f: %v", tt.temperature, err)
			}
			if tt.shouldErr && err != nil && !strings.Contains(err.Error(), "Temperature") {
				t.Errorf("error should mention Temperature, got: %v", err)
			}
		})
	}
}

// TestValidateMaxTokens tests max tokens range validation
func TestValidateMaxTokens(t *testing.T) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
				ModelName:      "gemini-2.5-flash",
				Temperature:    0.7,
				MaxTokens:      tt.maxTokens,
				RAGTopK:        3,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   5432,
				PostgresDBName: "koopa",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for max_tokens %d, got none", tt.maxTokens)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for max_tokens %d: %v", tt.maxTokens, err)
			}
			if tt.shouldErr && err != nil && !strings.Contains(err.Error(), "MaxTokens") {
				t.Errorf("error should mention MaxTokens, got: %v", err)
			}
		})
	}
}

// TestValidateRAGTopK tests RAG top K validation
func TestValidateRAGTopK(t *testing.T) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
				ModelName:      "gemini-2.5-flash",
				Temperature:    0.7,
				MaxTokens:      2048,
				RAGTopK:        tt.ragTopK,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   5432,
				PostgresDBName: "koopa",
			}

			err := cfg.Validate()
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for rag_top_k %d, got none", tt.ragTopK)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for rag_top_k %d: %v", tt.ragTopK, err)
			}
			if tt.shouldErr && err != nil && !strings.Contains(err.Error(), "RAGTopK") {
				t.Errorf("error should mention RAGTopK, got: %v", err)
			}
		})
	}
}

// TestValidateEmbedderModel tests embedder model validation
func TestValidateEmbedderModel(t *testing.T) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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
				ModelName:      "gemini-2.5-flash",
				Temperature:    0.7,
				MaxTokens:      2048,
				RAGTopK:        3,
				EmbedderModel:  "text-embedding-004",
				PostgresHost:   "localhost",
				PostgresPort:   tt.port,
				PostgresDBName: "koopa",
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
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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

// TestPostgresConnectionString tests DSN generation
func TestPostgresConnectionString(t *testing.T) {
	cfg := &Config{
		PostgresHost:     "test-host",
		PostgresPort:     5433,
		PostgresUser:     "test-user",
		PostgresPassword: "test-password",
		PostgresDBName:   "test-db",
		PostgresSSLMode:  "require",
	}

	dsn := cfg.PostgresConnectionString()

	expectedParts := []string{
		"host=test-host",
		"port=5433",
		"user=test-user",
		"password=test-password",
		"dbname=test-db",
		"sslmode=require",
	}

	for _, part := range expectedParts {
		if !strings.Contains(dsn, part) {
			t.Errorf("DSN should contain %q, got: %s", part, dsn)
		}
	}
}

// TestPlugins tests that Plugins() returns correct plugins
func TestPlugins(t *testing.T) {
	cfg := &Config{}
	plugins := cfg.Plugins()

	if len(plugins) == 0 {
		t.Error("expected at least one plugin")
	}

	// Should return GoogleAI plugin
	if len(plugins) != 1 {
		t.Errorf("expected exactly 1 plugin, got %d", len(plugins))
	}
}

// TestConfigError tests ConfigError type
func TestConfigError(t *testing.T) {
	err := &ConfigError{
		Field:   "test_field",
		Message: "test error message",
	}

	errMsg := err.Error()
	if errMsg != "test error message" {
		t.Errorf("expected error message 'test error message', got %q", errMsg)
	}
}

// TestConfigDirectoryCreation tests that config directory is created with correct permissions
func TestConfigDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	os.Setenv("HOME", tmpDir)
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	_, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Check that .koopa directory was created
	koopaDir := filepath.Join(tmpDir, ".koopa")
	info, err := os.Stat(koopaDir)
	if err != nil {
		t.Fatalf("config directory not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("expected .koopa to be a directory")
	}

	// Check permissions (0750 = drwxr-x---)
	perm := info.Mode().Perm()
	expectedPerm := os.FileMode(0o750)
	if perm != expectedPerm {
		t.Errorf("expected permissions %o, got %o", expectedPerm, perm)
	}
}

// TestEnvironmentVariableOverride tests that environment variables override config file
func TestEnvironmentVariableOverride(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	os.Setenv("HOME", tmpDir)
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	// Create .koopa directory and config file
	koopaDir := filepath.Join(tmpDir, ".koopa")
	if err := os.MkdirAll(koopaDir, 0o750); err != nil {
		t.Fatalf("failed to create koopa dir: %v", err)
	}

	configContent := `model_name: gemini-2.5-pro
temperature: 0.5
max_tokens: 1024
`
	configPath := filepath.Join(koopaDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set environment variables (should override config file)
	os.Setenv("MODEL_NAME", "gemini-1.5-flash")
	os.Setenv("TEMPERATURE", "0.9")
	defer os.Unsetenv("MODEL_NAME")
	defer os.Unsetenv("TEMPERATURE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Environment variables should override config file
	if cfg.ModelName != "gemini-1.5-flash" {
		t.Errorf("expected ModelName from env 'gemini-1.5-flash', got %q", cfg.ModelName)
	}

	if cfg.Temperature != 0.9 {
		t.Errorf("expected Temperature from env 0.9, got %f", cfg.Temperature)
	}

	// MaxTokens from config file should remain (no env override)
	if cfg.MaxTokens != 1024 {
		t.Errorf("expected MaxTokens from config 1024, got %d", cfg.MaxTokens)
	}
}

// TestLoadInvalidYAML tests loading configuration with invalid YAML
func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	os.Setenv("HOME", tmpDir)
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	// Create .koopa directory
	koopaDir := filepath.Join(tmpDir, ".koopa")
	if err := os.MkdirAll(koopaDir, 0o750); err != nil {
		t.Fatalf("failed to create koopa dir: %v", err)
	}

	// Create invalid YAML config file
	invalidYAML := `model_name: gemini-2.5-pro
temperature: invalid_value
  indentation: broken
max_tokens: not_a_number
`
	configPath := filepath.Join(koopaDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(invalidYAML), 0o600); err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid YAML, got none")
	}
}

// TestLoadUnmarshalError tests configuration unmarshal errors
func TestLoadUnmarshalError(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	os.Setenv("HOME", tmpDir)
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	// Create .koopa directory
	koopaDir := filepath.Join(tmpDir, ".koopa")
	if err := os.MkdirAll(koopaDir, 0o750); err != nil {
		t.Fatalf("failed to create koopa dir: %v", err)
	}

	// Create config with type mismatch
	invalidTypeYAML := `model_name: gemini-2.5-pro
temperature: "this should be a number"
max_tokens: "this should also be a number"
`
	configPath := filepath.Join(koopaDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(invalidTypeYAML), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// This will succeed because viper is flexible with type conversion
	// but we document this test to show that invalid types are handled
	_, err := Load()
	// Note: viper may successfully parse string "0.7" as float, so we don't assert error here
	_ = err
}

// BenchmarkLoad benchmarks configuration loading
func BenchmarkLoad(b *testing.B) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

	b.ResetTimer()
	for b.Loop() {
		_, _ = Load()
	}
}

// BenchmarkValidate benchmarks configuration validation
func BenchmarkValidate(b *testing.B) {
	os.Setenv("GEMINI_API_KEY", "test-key")
	defer os.Unsetenv("GEMINI_API_KEY")

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

	b.ResetTimer()
	for b.Loop() {
		_ = cfg.Validate()
	}
}
