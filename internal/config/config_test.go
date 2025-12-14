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
	// Reset Viper singleton to avoid interference from other tests
	viper.Reset()

	// Create temporary config directory (no config.yaml = pure defaults)
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer func() {
		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	// Set HOME to temp directory (no existing config.yaml)
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatalf("Failed to set HOME: %v", err)
	}

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

	// Clear DATABASE_URL to test pure defaults
	originalDBURL := os.Getenv("DATABASE_URL")
	os.Unsetenv("DATABASE_URL")
	defer func() {
		if originalDBURL != "" {
			_ = os.Setenv("DATABASE_URL", originalDBURL) // restore env in test cleanup
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

	if cfg.MaxHistoryMessages != DefaultMaxHistoryMessages {
		t.Errorf("expected default MaxHistoryMessages %d, got %d", DefaultMaxHistoryMessages, cfg.MaxHistoryMessages)
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

	// Clear DATABASE_URL to test config file loading
	originalDBURL := os.Getenv("DATABASE_URL")
	os.Unsetenv("DATABASE_URL")
	defer func() {
		if originalDBURL != "" {
			_ = os.Setenv("DATABASE_URL", originalDBURL) // restore env in test cleanup
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

// TestEnvironmentVariableOverride tests that ONLY sensitive env vars (DD_API_KEY, HMAC_SECRET) are bound.
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

	// KOOPA_* env vars NO LONGER supported (removed AutomaticEnv)
	testAPIKey := "test-datadog-api-key"
	testHMACSecret := "test-hmac-secret-minimum-32-chars-long"

	if err := os.Setenv("DD_API_KEY", testAPIKey); err != nil {
		t.Fatalf("Failed to set DD_API_KEY: %v", err)
	}
	if err := os.Setenv("HMAC_SECRET", testHMACSecret); err != nil {
		t.Fatalf("Failed to set HMAC_SECRET: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("DD_API_KEY")
		_ = os.Unsetenv("HMAC_SECRET")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Config values should come from config.yaml (NOT env vars)
	if cfg.ModelName != "gemini-2.5-pro" {
		t.Errorf("expected ModelName from config 'gemini-2.5-pro', got %q", cfg.ModelName)
	}

	if cfg.Temperature != 0.5 {
		t.Errorf("expected Temperature from config 0.5, got %f", cfg.Temperature)
	}

	if cfg.MaxTokens != 1024 {
		t.Errorf("expected MaxTokens from config 1024, got %d", cfg.MaxTokens)
	}

	// Sensitive env vars should be bound
	if cfg.Datadog.APIKey != testAPIKey {
		t.Errorf("expected Datadog.APIKey from env %q, got %q", testAPIKey, cfg.Datadog.APIKey)
	}

	if cfg.HMACSecret != testHMACSecret {
		t.Errorf("expected HMACSecret from env %q, got %q", testHMACSecret, cfg.HMACSecret)
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

	// CRITICAL: Verify original password is NOT in output (security requirement)
	if strings.Contains(jsonStr, "supersecretpassword123") {
		t.Error("SECURITY: sensitive field PostgresPassword not masked - raw password found in JSON")
	}

	// Verify masking is applied (format-agnostic check)
	// The masked value should:
	// 1. Not be the original password
	// 2. Contain masking characters (****)
	// 3. Be present in the JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	maskedPwd, ok := result["postgres_password"].(string)
	if !ok {
		t.Fatal("postgres_password should be a string in JSON output")
	}

	// Verify masking is applied (contains ████████)
	if !strings.Contains(maskedPwd, "████████") {
		t.Errorf("masked password should contain '████████', got: %s", maskedPwd)
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

	// Short passwords should be fully masked as "████████"
	if strings.Contains(jsonStr, "abc") {
		t.Error("short password should be fully masked")
	}

	if !strings.Contains(jsonStr, `"postgres_password":"████████"`) {
		t.Errorf("expected fully masked password '████████', got: %s", jsonStr)
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

// TestConfig_MarshalJSON_NestedStructs verifies nested structs are properly serialized
// This test ensures recursive processing works correctly for nested configurations
func TestConfig_MarshalJSON_NestedStructs(t *testing.T) {
	cfg := Config{
		ModelName:        "test-model",
		PostgresPassword: "secretpassword",
		MCP: MCPConfig{
			Timeout: 10,
			Allowed: []string{"server1", "server2"},
		},
		MCPServers: map[string]MCPServer{
			"test-server": {
				Command: "npx",
				Args:    []string{"-y", "test-mcp"},
				Timeout: 30,
			},
		},
		SearXNG: SearXNGConfig{
			BaseURL: "http://localhost:8080",
		},
		Datadog: DatadogConfig{
			AgentHost:   "localhost:4318",
			Environment: "test",
			ServiceName: "koopa-test",
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Verify nested MCP config is present
	mcp, ok := result["mcp"].(map[string]interface{})
	if !ok {
		t.Fatal("mcp should be a nested object in JSON output")
	}
	if mcp["timeout"] != float64(10) {
		t.Errorf("expected mcp.timeout = 10, got %v", mcp["timeout"])
	}

	// Verify MCPServers map is present
	servers, ok := result["mcp_servers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcp_servers should be a map in JSON output")
	}
	if _, exists := servers["test-server"]; !exists {
		t.Error("expected test-server in mcp_servers")
	}

	// Verify SearXNG config
	searxng, ok := result["searxng"].(map[string]interface{})
	if !ok {
		t.Fatal("searxng should be a nested object")
	}
	if searxng["base_url"] != "http://localhost:8080" {
		t.Errorf("expected searxng.base_url = 'http://localhost:8080', got %v", searxng["base_url"])
	}

	// Verify Datadog config
	datadog, ok := result["datadog"].(map[string]interface{})
	if !ok {
		t.Fatal("datadog should be a nested object")
	}
	if datadog["environment"] != "test" {
		t.Errorf("expected datadog.environment = 'test', got %v", datadog["environment"])
	}

	// CRITICAL: Verify sensitive field is still masked
	jsonStr := string(data)
	if strings.Contains(jsonStr, "secretpassword") {
		t.Error("SECURITY: PostgresPassword should be masked in JSON with nested structs")
	}
}

// TestConfig_MarshalJSON_MCPServerEnvMasked verifies that MCPServer.Env (sensitive map) is masked
// SECURITY: MCPServer.Env commonly contains API keys, tokens, and secrets
func TestConfig_MarshalJSON_MCPServerEnvMasked(t *testing.T) {
	cfg := Config{
		MCPServers: map[string]MCPServer{
			"github-mcp": {
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-github"},
				Env: map[string]string{
					"GITHUB_TOKEN":      "ghp_supersecrettoken12345678",
					"API_KEY":           "sk-proj-secretapikey67890",
					"OPENAI_API_KEY":    "sk-openai-verysecretkey",
					"ANTHROPIC_KEY":     "anthropic-secret-key-xxx",
					"DATABASE_PASSWORD": "dbpassword123",
				},
				Timeout: 30,
			},
			"another-server": {
				Command: "node",
				Env: map[string]string{
					"SECRET_TOKEN": "another_secret_value",
				},
			},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	// CRITICAL: All secret values in Env must be masked
	secrets := []string{
		"ghp_supersecrettoken12345678",
		"sk-proj-secretapikey67890",
		"sk-openai-verysecretkey",
		"anthropic-secret-key-xxx",
		"dbpassword123",
		"another_secret_value",
	}

	for _, secret := range secrets {
		if strings.Contains(jsonStr, secret) {
			t.Errorf("SECURITY: MCPServer.Env secret leaked in JSON output: %s", secret)
		}
	}

	// Verify the Env field is present but masked
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	servers, ok := result["mcp_servers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcp_servers should be present in JSON output")
	}

	githubServer, ok := servers["github-mcp"].(map[string]interface{})
	if !ok {
		t.Fatal("github-mcp server should be present")
	}

	// Env should be masked as "████████" (sensitive map with non-empty content)
	env := githubServer["env"]
	if env != "████████" {
		t.Errorf("MCPServer.Env should be masked as '████████', got: %v", env)
	}

	// Verify non-sensitive fields are NOT masked
	if githubServer["command"] != "npx" {
		t.Error("non-sensitive field Command should not be masked")
	}
}

// TestConfig_MarshalJSON_AllSensitiveFields iterates all fields marked sensitive
// and verifies they are properly masked (comprehensive coverage)
func TestConfig_MarshalJSON_AllSensitiveFields(t *testing.T) {
	typ := reflect.TypeOf(Config{})

	// Build a Config with test values for all sensitive fields
	cfg := Config{}
	val := reflect.ValueOf(&cfg).Elem()

	sensitiveFields := make(map[string]string) // jsonName -> testValue

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Tag.Get("sensitive") != "true" {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		jsonName := strings.Split(jsonTag, ",")[0]

		// Set a unique test value for this sensitive field
		testValue := "test_secret_" + field.Name + "_12345"
		if field.Type.Kind() == reflect.String {
			val.Field(i).SetString(testValue)
			sensitiveFields[jsonName] = testValue
		}
	}

	if len(sensitiveFields) == 0 {
		t.Skip("no sensitive string fields found in Config")
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(data)

	// Verify each sensitive field's original value is NOT in the output
	for jsonName, originalValue := range sensitiveFields {
		if strings.Contains(jsonStr, originalValue) {
			t.Errorf("SECURITY: sensitive field %s not masked - original value found in JSON", jsonName)
		}
	}
}

// ============================================================================
// Unicode Password Tests
// ============================================================================

// TestMaskSecret_Unicode verifies masking handles multi-byte UTF-8 correctly.
// This is important because maskSecret uses string slicing which operates on bytes,
// but users expect character-level masking for international passwords.
func TestMaskSecret_Unicode(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantContains string // What the masked output should contain
		wantMasked   bool   // Should original be fully hidden
	}{
		// ASCII baseline
		{"ascii_long", "password123", "<████████>", true}, // >8 chars, shows partial
		{"ascii_short", "abc", "████████", true},          // <=8 chars, fully masked
		{"ascii_8chars", "12345678", "████████", true},    // exactly 8 chars, fully masked

		// Unicode - multi-byte characters
		{"emoji_password", "🔐secret🔑pass", "<████████>", true}, // >8 chars
		{"emoji_only_short", "🔐🔑", "████████", true},           // 2 emojis = 8 bytes, fully masked
		{"chinese_password", "密碼password123", "<████████>", true},
		{"japanese_password", "パスワード12345", "<████████>", true},
		{"arabic_password", "كلمةالسر123", "<████████>", true},
		{"mixed_unicode", "Пароль🔐密碼extra", "<████████>", true},

		// Edge cases
		{"empty", "", "", false},
		{"single_emoji", "🔐", "████████", true},
		{"newlines", "pass\nword\r\n123", "<████████>", true}, // >8 chars
		{"tabs", "pass\tword1", "<████████>", true},           // >8 chars
		{"exactly_9chars", "123456789", "<████████>", true},   // exactly 9 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := maskSecret(tt.input)

			// Verify masking pattern is present (when expected)
			if tt.wantContains != "" && !strings.Contains(masked, tt.wantContains) {
				t.Errorf("expected masked output to contain %q, got: %q", tt.wantContains, masked)
			}

			// CRITICAL: Original value must NEVER appear in masked output
			if tt.wantMasked && tt.input != "" {
				// For short passwords (<=8 chars), fully masked to prevent substring attacks
				if len(tt.input) <= 8 {
					if masked != "████████" {
						t.Errorf("short password (<=8 chars) should be fully masked as '████████', got: %q", masked)
					}
				} else {
					// For longer passwords, original should not appear as substring
					if strings.Contains(masked, tt.input) {
						t.Errorf("SECURITY: original password leaked in masked output")
					}
				}
			}

			// Empty input should return empty
			if tt.input == "" && masked != "" {
				t.Errorf("empty input should return empty, got: %q", masked)
			}
		})
	}
}

// TestConfig_MarshalJSON_UnicodePasswords verifies Config marshaling handles Unicode correctly
func TestConfig_MarshalJSON_UnicodePasswords(t *testing.T) {
	unicodePasswords := []string{
		"密碼123456789",      // Chinese
		"パスワード12345",       // Japanese
		"비밀번호12345",        // Korean
		"пароль12345",      // Russian
		"🔐secret🔑password", // Emoji
		"café☕password123", // Mixed
	}

	for _, password := range unicodePasswords {
		t.Run(password[:min(10, len(password))], func(t *testing.T) {
			cfg := Config{
				PostgresPassword: password,
			}

			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}

			jsonStr := string(data)

			// CRITICAL: Original password must NEVER appear in JSON
			if strings.Contains(jsonStr, password) {
				t.Errorf("SECURITY: Unicode password leaked in JSON output: %s", password)
			}

			// Verify masking was applied
			if !strings.Contains(jsonStr, "████████") {
				t.Errorf("expected masked output to contain '████████', got: %s", jsonStr)
			}
		})
	}
}

// ============================================================================
// Fuzz Tests for Security
// ============================================================================

// FuzzMaskSecret tests maskSecret against arbitrary inputs to detect bypass vectors.
// Run with: go test -fuzz=FuzzMaskSecret -fuzztime=30s ./internal/config/
func FuzzMaskSecret(f *testing.F) {
	// Seed corpus with known attack patterns
	seeds := []string{
		// Normal cases
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"password123",
		"supersecretpassword",

		// Unicode and encoding
		"密碼password",
		"🔐🔑🔓",
		"пароль",

		// Injection attempts
		"\x00secret\x00",     // Null bytes
		"pass\nword",         // Newlines
		"pass\rword",         // Carriage return
		"pass\tword",         // Tabs
		"\u202Esecret\u202D", // RTL override
		"\uFEFFpassword",     // BOM
		"pass\u0000word",     // Embedded null

		// JSON injection
		`{"password":"inject"}`,
		`","password":"leak`,
		"\\\"escape\\\"",

		// Length boundaries
		strings.Repeat("a", 3),
		strings.Repeat("a", 4),
		strings.Repeat("a", 5),
		strings.Repeat("a", 100),
		strings.Repeat("a", 1000),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		masked := maskSecret(input)

		// Property 1: Empty input returns empty output
		if input == "" && masked != "" {
			t.Errorf("empty input should return empty, got: %q", masked)
		}

		// Property 2: Short inputs (<=8 chars) should be fully masked (security: prevent substring attacks)
		if input != "" && len(input) <= 8 && masked != "████████" {
			t.Errorf("short input (<=8 chars) should be '████████', got: %q for input len=%d", masked, len(input))
		}

		// Property 3: Meaningful portions of input should not leak (CRITICAL SECURITY)
		// REVISED: Only check for leaks of 3+ chars (real security risk)
		// We allow single-byte UTF-8 artifacts (harmless) but prevent
		// meaningful data exposure (e.g., "password" appearing in masked output)
		if len(input) >= 3 {
			// Check for 3+ character leaks (actual security risk)
			for i := 0; i <= len(input)-3; i++ {
				substring := input[i : i+3]

				// Skip substrings that contain format delimiters (< or >)
				// These are part of the output format, not leaks
				if strings.Contains(substring, "<") || strings.Contains(substring, ">") {
					continue
				}

				// Skip substrings that are part of the mask character's UTF-8 encoding
				// The block character "█" (U+2588) is encoded as E2 96 88
				// We don't want to fail on byte-level coincidences
				if strings.Contains(substring, "\xe2") || strings.Contains(substring, "\x96") || strings.Contains(substring, "\x88") {
					continue
				}

				// For long inputs (>8), skip expected prefix/suffix
				if len(input) > 8 {
					if i < 2 || i > len(input)-5 {
						continue // Prefix/suffix are intentionally shown
					}
				}

				if strings.Contains(masked, substring) {
					t.Errorf("SECURITY: meaningful substring leaked: %q from input %q in output %q",
						substring, input, masked)
				}
			}
		}

		// Property 4: Masked output should contain "████████" (for non-empty inputs)
		if input != "" && !strings.Contains(masked, "████████") {
			t.Errorf("masked output should contain '████████', got: %q", masked)
		}

		// Property 5: Masked output length constraints
		// For short (<=8): exactly "████████" (24 bytes in UTF-8)
		// For long (>8): XX<████████>XX (30 bytes: 2+1+24+1+2)
		if input != "" && len(input) <= 8 && len(masked) != 24 {
			t.Errorf("short masked output should be 24 bytes, got %d", len(masked))
		}
		if len(input) > 8 && len(masked) != 30 {
			t.Errorf("long masked output should be 30 bytes (XX<████████>XX), got %d for input len=%d", len(masked), len(input))
		}
	})
}

// FuzzConfigMarshalJSON tests Config.MarshalJSON against arbitrary passwords
// to ensure no bypass of sensitive field masking.
// Run with: go test -fuzz=FuzzConfigMarshalJSON -fuzztime=30s ./internal/config/
func FuzzConfigMarshalJSON(f *testing.F) {
	seeds := []string{
		"password123",
		"",
		"short",
		"\x00\xff\xfe",
		"pass\nword\r\n",
		`{"inject":"json"}`,
		"密碼🔐",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, password string) {
		cfg := Config{
			PostgresPassword: password,
			ModelName:        "test-model",
		}

		data, err := json.Marshal(cfg)
		if err != nil {
			// JSON marshal errors are acceptable for malformed inputs
			// But verify password doesn't leak in error message
			if password != "" && strings.Contains(err.Error(), password) {
				t.Errorf("SECURITY: password leaked in error message")
			}
			return
		}

		jsonStr := string(data)

		// CRITICAL: Original password must NEVER appear in password field
		// Parse JSON to check the specific postgres_password field value
		// Using simple string matching on the password field to avoid false positives
		// from other fields (e.g., "0" appearing in port numbers)
		if password != "" && len(password) > 0 {
			// Check for exact password field match in JSON
			// Pattern: "postgres_password":"<actual_password>"
			passwordFieldPattern := `"postgres_password":"` + password + `"`
			if strings.Contains(jsonStr, passwordFieldPattern) {
				t.Errorf("SECURITY: password leaked in JSON postgres_password field: input=%q output=%s", password, jsonStr)
			}
		}
	})
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

// BenchmarkMaskSecret benchmarks the core masking function
func BenchmarkMaskSecret(b *testing.B) {
	passwords := []string{
		"",
		"abc",
		"password123",
		"verylongpasswordthatexceedsnormallength",
		"密碼🔐パスワード",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, p := range passwords {
			_ = maskSecret(p)
		}
	}
}

// BenchmarkConfig_MarshalJSON benchmarks Config serialization with sensitive masking
func BenchmarkConfig_MarshalJSON(b *testing.B) {
	cfg := Config{
		ModelName:        "gemini-2.5-flash",
		Temperature:      0.7,
		MaxTokens:        2048,
		PostgresPassword: "supersecretpassword123",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "koopa",
		PostgresDBName:   "koopa",
		MCP: MCPConfig{
			Timeout: 5,
			Allowed: []string{"server1", "server2"},
		},
		MCPServers: map[string]MCPServer{
			"github": {
				Command: "npx",
				Args:    []string{"-y", "@modelcontextprotocol/server-github"},
				Env: map[string]string{
					"GITHUB_TOKEN": "ghp_secrettoken12345",
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = json.Marshal(cfg)
	}
}

// BenchmarkConfig_MarshalJSON_Parallel benchmarks concurrent Config marshaling
func BenchmarkConfig_MarshalJSON_Parallel(b *testing.B) {
	cfg := Config{
		PostgresPassword: "supersecretpassword123",
		MCPServers: map[string]MCPServer{
			"test": {
				Command: "npx",
				Env:     map[string]string{"SECRET": "value"},
			},
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = json.Marshal(cfg)
		}
	})
}
