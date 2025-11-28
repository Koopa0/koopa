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
		ragTopK   int32
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

// TestValidateBranch tests branch name validation
func TestValidateBranch(t *testing.T) {
	tests := []struct {
		name      string
		branch    string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{"empty defaults to main", "", DefaultBranch, false, ""},
		{"simple main", "main", "main", false, ""},
		{"single segment", "chat", "chat", false, ""},
		{"two segments", "main.research", "main.research", false, ""},
		{"three segments", "main.agent1.subtask", "main.agent1.subtask", false, ""},
		{"with underscore", "main_branch", "main_branch", false, ""},
		{"segment with number", "agent1", "agent1", false, ""},
		{"complex valid", "Chat.Agent_1.SubTask2", "Chat.Agent_1.SubTask2", false, ""},
		{"starts with number", "1agent", "", true, "must start with a letter"},
		{"starts with underscore", "_main", "", true, "must start with a letter"},
		{"starts with dot", ".main", "", true, "empty segment"},
		{"ends with dot", "main.", "", true, "empty segment"},
		{"consecutive dots", "main..sub", "", true, "empty segment"},
		{"has space", "main sub", "", true, "alphanumeric"},
		{"has dash", "main-sub", "", true, "alphanumeric"},
		{"has special char", "main@sub", "", true, "alphanumeric"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateBranch(tt.branch)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateBranch(%q) expected error, got nil", tt.branch)
					return
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ValidateBranch(%q) error = %v, want error containing %q", tt.branch, err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateBranch(%q) unexpected error: %v", tt.branch, err)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateBranch(%q) = %q, want %q", tt.branch, got, tt.want)
			}
		})
	}
}

// TestValidateBranchLengthLimit tests branch length validation
func TestValidateBranchLengthLimit(t *testing.T) {
	longBranch := strings.Repeat("a", MaxBranchLength+1)
	_, err := ValidateBranch(longBranch)
	if err == nil {
		t.Error("ValidateBranch() expected error for branch exceeding max length")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error should mention 'too long', got: %v", err)
	}

	exactBranch := "a" + strings.Repeat("b", MaxBranchLength-1)
	_, err = ValidateBranch(exactBranch)
	if err != nil {
		t.Errorf("ValidateBranch() unexpected error for branch at max length: %v", err)
	}
}

// TestValidateBranchDepthLimit tests branch depth validation
func TestValidateBranchDepthLimit(t *testing.T) {
	segments := make([]string, MaxBranchDepth+1)
	for i := range segments {
		segments[i] = "a"
	}
	deepBranch := strings.Join(segments, ".")

	_, err := ValidateBranch(deepBranch)
	if err == nil {
		t.Error("ValidateBranch() expected error for branch exceeding max depth")
	}
	if !strings.Contains(err.Error(), "too deep") {
		t.Errorf("error should mention 'too deep', got: %v", err)
	}

	exactSegments := make([]string, MaxBranchDepth)
	for i := range exactSegments {
		exactSegments[i] = "a"
	}
	exactBranch := strings.Join(exactSegments, ".")

	_, err = ValidateBranch(exactBranch)
	if err != nil {
		t.Errorf("ValidateBranch() unexpected error for branch at max depth: %v", err)
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

// TestBranchValidationErrors tests that branch validation returns correct sentinel errors
func TestBranchValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		branch   string
		sentinel error
	}{
		{"too long", strings.Repeat("a", MaxBranchLength+1), ErrBranchTooLong},
		{"too deep", "a.b.c.d.e.f.g.h.i.j.k", ErrBranchTooDeep},
		{"empty segment", "invalid..branch", ErrInvalidBranch},
		{"leading dot", ".invalid", ErrInvalidBranch},
		{"trailing dot", "invalid.", ErrInvalidBranch},
		{"number start", "123abc", ErrInvalidBranch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateBranch(tt.branch)
			if err == nil {
				t.Errorf("ValidateBranch(%q) = nil, want error", tt.branch)
				return
			}
			if !errors.Is(err, tt.sentinel) {
				t.Errorf("ValidateBranch(%q) error = %v, want errors.Is(%v)", tt.branch, err, tt.sentinel)
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
		ModelName:      "gemini-2.5-flash",
		Temperature:    0.7,
		MaxTokens:      2048,
		RAGTopK:        3,
		EmbedderModel:  "text-embedding-004",
		PostgresHost:   "localhost",
		PostgresPort:   5432,
		PostgresDBName: "koopa",
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
