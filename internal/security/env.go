package security

import (
	"fmt"
	"log/slog"
	"strings"
)

// Env validates environment variable access to prevent information leakage.
// Used to prevent sensitive information leakage.
type Env struct {
	sensitivePatterns []string
}

// NewEnv creates a new Env validator.
func NewEnv() *Env {
	return &Env{
		sensitivePatterns: []string{
			// API keys and authentication credentials
			"API_KEY",
			"APIKEY",
			"SECRET",
			"PASSWORD",
			"PASSWD",
			"PWD",
			"TOKEN",
			"ACCESS_TOKEN",
			"REFRESH_TOKEN",
			"AUTH",
			"CREDENTIALS",
			"PRIVATE_KEY",
			"PRIV_KEY",

			// Cloud services related
			"AWS_SECRET",
			"AWS_ACCESS_KEY",
			"AZURE_",
			"GCP_",
			"GOOGLE_API",
			"GOOGLE_APPLICATION_CREDENTIALS",

			// Database related
			"DB_PASSWORD",
			"DB_PASS",
			"DATABASE_PASSWORD",
			"DATABASE_URL", // May contain password
			"REDIS_PASSWORD",
			"MONGO_PASSWORD",
			"POSTGRES_PASSWORD",
			"MYSQL_PASSWORD",

			// OAuth and third-party services
			"OAUTH",
			"GITHUB_TOKEN",
			"GITLAB_TOKEN",
			"SLACK_TOKEN",
			"DISCORD_TOKEN",
			"TELEGRAM_TOKEN",

			// Encryption related
			"ENCRYPTION_KEY",
			"ENCRYPT_KEY",
			"CIPHER_KEY",
			"SALT",
			"HASH_KEY",
			"SIGNING_KEY",

			// Email services
			"SMTP_PASSWORD",
			"MAIL_PASSWORD",
			"EMAIL_PASSWORD",

			// Payment related
			"STRIPE_SECRET",
			"PAYPAL_SECRET",
			"PAYMENT_KEY",

			// Session and Cookie
			"SESSION_SECRET",
			"COOKIE_SECRET",

			// AI services (Gemini, OpenAI, etc.)
			"GEMINI_API_KEY",
			"OPENAI_API_KEY",
			"ANTHROPIC_API_KEY",
			"HUGGINGFACE_TOKEN",
		},
	}
}

// ValidateEnvAccess validates whether access to the specified environment variable is allowed
func (v *Env) ValidateEnvAccess(envName string) error {
	envUpper := strings.ToUpper(envName)

	// Check if it matches sensitive patterns
	for _, pattern := range v.sensitivePatterns {
		if strings.Contains(envUpper, pattern) {
			slog.Warn("sensitive environment variable access attempt",
				"env_name", envName,
				"matched_pattern", pattern,
				"security_event", "sensitive_env_access")
			return fmt.Errorf("access denied to sensitive environment variable: %s (matched pattern: %s)", envName, pattern)
		}
	}

	return nil
}
