package security

import (
	"fmt"
	"strings"
)

// EnvValidator environment variable validator
// Used to prevent sensitive information leakage
type EnvValidator struct {
	sensitivePatterns []string
}

// NewEnvValidator creates an environment variable validator
func NewEnvValidator() *EnvValidator {
	return &EnvValidator{
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
func (v *EnvValidator) ValidateEnvAccess(envName string) error {
	envUpper := strings.ToUpper(envName)

	// Check if it matches sensitive patterns
	for _, pattern := range v.sensitivePatterns {
		if strings.Contains(envUpper, pattern) {
			return fmt.Errorf("access denied to sensitive environment variable: %s (matched pattern: %s)", envName, pattern)
		}
	}

	return nil
}

// IsSensitiveEnv quickly checks if an environment variable name is obviously sensitive
// This is an additional layer of protection
func IsSensitiveEnv(envName string) bool {
	envUpper := strings.ToUpper(envName)

	quickPatterns := []string{
		"SECRET",
		"PASSWORD",
		"TOKEN",
		"KEY",
		"CREDENTIALS",
	}

	for _, pattern := range quickPatterns {
		if strings.Contains(envUpper, pattern) {
			return true
		}
	}

	return false
}

// GetAllowedEnvNames retrieves the list of explicitly allowed environment variables (whitelist)
// These are common non-sensitive environment variables
func GetAllowedEnvNames() []string {
	return []string{
		// System information
		"PATH",
		"HOME",
		"USER",
		"SHELL",
		"TERM",
		"LANG",
		"LC_ALL",
		"TZ",

		// Go related
		"GOPATH",
		"GOROOT",
		"GOOS",
		"GOARCH",
		"GO111MODULE",

		// General development
		"EDITOR",
		"VISUAL",
		"PAGER",

		// Proxy settings (without authentication)
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",

		// Log levels
		"LOG_LEVEL",
		"DEBUG",

		// Application name and version (non-sensitive)
		"APP_NAME",
		"APP_VERSION",
		"NODE_ENV",
		"ENVIRONMENT",
	}
}
