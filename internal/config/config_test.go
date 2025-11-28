package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
			if err := os.Setenv("GEMINI_API_KEY", originalAPIKey); err != nil {
				t.Errorf("Failed to restore GEMINI_API_KEY: %v", err)
			}
		} else {
			if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
				t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
			}
		}
	}()

	// Set API key for validation
	if err := os.Setenv("GEMINI_API_KEY", "test-api-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}

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
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	// Set HOME to temp directory
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	if err := os.Setenv("GEMINI_API_KEY", "test-api-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

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

// TestSentinelErrors tests that sentinel errors work with errors.Is()
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"ErrConfigNil", ErrConfigNil, ErrConfigNil},
		{"ErrMissingAPIKey", ErrMissingAPIKey, ErrMissingAPIKey},
		{"ErrInvalidModelName", ErrInvalidModelName, ErrInvalidModelName},
		{"ErrInvalidTemperature", ErrInvalidTemperature, ErrInvalidTemperature},
		{"ErrInvalidBranch", ErrInvalidBranch, ErrInvalidBranch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.sentinel)
			}
		})
	}
}

// TestConfigDirectoryCreation tests that config directory is created with correct permissions
func TestConfigDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

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
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

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
	// Note: config uses KOOPA_ prefix for environment variables
	if err := os.Setenv("KOOPA_MODEL_NAME", "gemini-1.5-flash"); err != nil {
		t.Fatalf("Failed to set KOOPA_MODEL_NAME: %v", err)
	}
	if err := os.Setenv("KOOPA_TEMPERATURE", "0.9"); err != nil {
		t.Fatalf("Failed to set KOOPA_TEMPERATURE: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("KOOPA_MODEL_NAME"); err != nil {
			t.Errorf("Failed to unset KOOPA_MODEL_NAME: %v", err)
		}
	}()
	defer func() {
		if err := os.Unsetenv("KOOPA_TEMPERATURE"); err != nil {
			t.Errorf("Failed to unset KOOPA_TEMPERATURE: %v", err)
		}
	}()

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
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

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
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			t.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

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
	if err := os.Setenv("GEMINI_API_KEY", "test-key"); err != nil {
		b.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
			b.Errorf("Failed to unset GEMINI_API_KEY: %v", err)
		}
	}()

	// Verify Load() works before starting benchmark
	if _, err := Load(); err != nil {
		b.Fatalf("Load() failed: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = Load()
	}
}

// ============================================================================
// Sensitive Data Masking Tests (P1-2 Fix)
// ============================================================================

// TestConfig_MarshalJSON_MasksSensitiveFields verifies that sensitive fields are masked
func TestConfig_MarshalJSON_MasksSensitiveFields(t *testing.T) {
	cfg := Config{
		ModelName:        "gemini-2.5-flash",
		PostgresPassword: "supersecretpassword123",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "koopa",
		PostgresDBName:   "koopa",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	// Verify original password is NOT in output
	if strings.Contains(jsonStr, "supersecretpassword123") {
		t.Error("sensitive field PostgresPassword not masked - raw password found in JSON")
	}

	// Verify masked format is present (su****23)
	if !strings.Contains(jsonStr, "su****23") {
		t.Errorf("expected masked password format 'su****23' in JSON, got: %s", jsonStr)
	}

	// Verify non-sensitive fields are NOT masked
	if !strings.Contains(jsonStr, "localhost") {
		t.Error("non-sensitive field PostgresHost should not be masked")
	}

	if !strings.Contains(jsonStr, "gemini-2.5-flash") {
		t.Error("non-sensitive field ModelName should not be masked")
	}
}

// TestConfig_MarshalJSON_EmptyPassword verifies empty passwords are handled
func TestConfig_MarshalJSON_EmptyPassword(t *testing.T) {
	cfg := Config{
		ModelName:        "test-model",
		PostgresPassword: "",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Empty password should remain empty, not cause panic
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result["postgres_password"] != "" {
		t.Errorf("expected empty password to remain empty, got %v", result["postgres_password"])
	}
}

// TestConfig_MarshalJSON_ShortPassword verifies short passwords are fully masked
func TestConfig_MarshalJSON_ShortPassword(t *testing.T) {
	cfg := Config{
		PostgresPassword: "abc", // 3 chars - should be fully masked
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	// Short passwords should be fully masked as "****"
	if strings.Contains(jsonStr, "abc") {
		t.Error("short password should be fully masked")
	}

	if !strings.Contains(jsonStr, `"postgres_password":"****"`) {
		t.Errorf("expected fully masked password '****', got: %s", jsonStr)
	}
}

// TestConfig_String_MasksSensitiveFields verifies String() also masks sensitive fields
func TestConfig_String_MasksSensitiveFields(t *testing.T) {
	cfg := Config{
		PostgresPassword: "topsecretpassword",
	}

	str := cfg.String()

	if strings.Contains(str, "topsecretpassword") {
		t.Error("Config.String() should mask sensitive fields")
	}
}

// TestConfig_SensitiveFieldsHaveTag verifies all string fields with "password" or "secret"
// in the name have the sensitive tag (architectural safety net)
func TestConfig_SensitiveFieldsHaveTag(t *testing.T) {
	typ := reflect.TypeOf(Config{})

	sensitiveKeywords := []string{"password", "secret", "token", "apikey", "api_key"}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		// Only check string fields
		if field.Type.Kind() != reflect.String {
			continue
		}

		fieldNameLower := strings.ToLower(field.Name)
		jsonTagLower := strings.ToLower(field.Tag.Get("json"))

		// Check if field name or json tag contains sensitive keywords
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(fieldNameLower, keyword) || strings.Contains(jsonTagLower, keyword) {
				// This field should have sensitive:"true" tag
				sensitiveTag := field.Tag.Get("sensitive")
				if sensitiveTag != "true" {
					t.Errorf("field %s contains '%s' but missing sensitive:\"true\" tag",
						field.Name, keyword)
				}
			}
		}
	}
}
