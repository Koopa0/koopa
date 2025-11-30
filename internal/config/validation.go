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

// ValidateBranch validates a branch name according to the following rules:
//   - Branch format: "segment" or "segment1.segment2.segment3"
//   - Each segment must start with a letter and contain only alphanumeric chars and underscores
//   - Maximum total length is MaxBranchLength (256)
//   - Maximum depth is MaxBranchDepth (10 segments)
//   - Empty branch defaults to DefaultBranch ("main")
//
// Returns sentinel errors that can be checked with errors.Is():
//   - ErrBranchTooLong: branch exceeds MaxBranchLength
//   - ErrBranchTooDeep: branch exceeds MaxBranchDepth
//   - ErrInvalidBranch: branch format is invalid
//
// Examples of valid branches: "main", "main.research", "chat.agent1.subtask"
// Examples of invalid branches: ".main", "main.", "main..sub", "123abc"
func ValidateBranch(branch string) (string, error) {
	if branch == "" {
		return DefaultBranch, nil
	}

	if len(branch) > MaxBranchLength {
		return "", fmt.Errorf("%w: %q exceeds max %d characters", ErrBranchTooLong, branch, MaxBranchLength)
	}

	segments := splitBranch(branch)
	if len(segments) > MaxBranchDepth {
		return "", fmt.Errorf("%w: %q exceeds max %d levels", ErrBranchTooDeep, branch, MaxBranchDepth)
	}

	for i, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("%w: %q has empty segment (consecutive dots or leading/trailing dot)", ErrInvalidBranch, branch)
		}
		if !isValidSegment(seg) {
			return "", fmt.Errorf("%w: segment %d %q must start with a letter and contain only alphanumeric characters and underscores", ErrInvalidBranch, i+1, seg)
		}
	}

	return branch, nil
}

// NormalizeBranch normalizes and validates a branch name.
func NormalizeBranch(branch string) (string, error) {
	return ValidateBranch(branch)
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

// splitBranch splits a branch name by dots.
func splitBranch(branch string) []string {
	if branch == "" {
		return []string{}
	}

	var segments []string
	start := 0
	for i := range branch {
		if branch[i] == '.' {
			segments = append(segments, branch[start:i])
			start = i + 1
		}
	}
	segments = append(segments, branch[start:])
	return segments
}

// isValidSegment checks if a branch segment is valid.
func isValidSegment(seg string) bool {
	if seg == "" {
		return false
	}

	// First character must be a letter (De Morgan's law applied)
	first := seg[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return false
	}

	// Remaining characters must be alphanumeric or underscore (De Morgan's law applied)
	for i := 1; i < len(seg); i++ {
		c := seg[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}

	return true
}
