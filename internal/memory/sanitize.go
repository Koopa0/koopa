package memory

import (
	"regexp"
	"strings"
)

// RedactedPlaceholder replaces lines containing secrets.
const RedactedPlaceholder = "[REDACTED]"

// secretPatterns are compiled regexes that match common secret formats.
// Favors false positives over false negatives — better to redact too much
// than to let a real secret through to memory storage.
var secretPatterns = []*regexp.Regexp{
	// API keys by provider prefix
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{20,}`),                        // OpenAI
	regexp.MustCompile(`(?i)sk-ant-[a-zA-Z0-9\-]{20,}`),                  // Anthropic
	regexp.MustCompile(`AIza[a-zA-Z0-9\-_]{35}`),                         // Google API
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),                        // GitHub PAT
	regexp.MustCompile(`(?i)gho_[a-zA-Z0-9]{36}`),                        // GitHub OAuth
	regexp.MustCompile(`(?i)github_pat_[a-zA-Z0-9_]{22,}`),               // GitHub fine-grained
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),                               // AWS access key
	regexp.MustCompile(`(?i)xox[bpsa]-[a-zA-Z0-9\-]{10,}`),               // Slack tokens
	regexp.MustCompile(`(?i)ya29\.[a-zA-Z0-9_\-]{50,}`),                  // Google OAuth
	regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]+`), // JWT
	regexp.MustCompile(`(?i)sk_(?:live|test)_[a-zA-Z0-9]{24,}`),          // Stripe
	regexp.MustCompile(`(?i)rk_(?:live|test)_[a-zA-Z0-9]{24,}`),          // Stripe restricted
	regexp.MustCompile(`(?i)AC[a-f0-9]{32}`),                             // Twilio account SID
	regexp.MustCompile(`(?i)SK[a-f0-9]{32}`),                             // Twilio API key

	// Connection strings
	regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis)://\S+@\S+`),

	// PEM private keys
	regexp.MustCompile(`-{5}BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-{5}`),

	// Bearer tokens in headers
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}`),

	// Generic key=value patterns for common secret names
	regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|private[_-]?key|auth[_-]?token)\s*[:=]\s*["']?[a-zA-Z0-9\-_.]{16,}["']?`),

	// Password assignments
	regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}["']?`),
}

// ContainsSecrets reports whether text contains any known secret pattern.
func ContainsSecrets(text string) bool {
	for _, p := range secretPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// SanitizeLines processes text line by line, replacing lines that contain
// secrets with "[REDACTED]". Lines without secrets pass through unchanged.
func SanitizeLines(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if ContainsSecrets(line) {
			lines[i] = RedactedPlaceholder
		}
	}
	return strings.Join(lines, "\n")
}
