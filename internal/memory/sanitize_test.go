package memory

import (
	"strings"
	"testing"
)

// fakeKey builds a test key at runtime to avoid triggering GitHub push protection.
func fakeKey(prefix string, n int) string {
	return prefix + strings.Repeat("X", n)
}

// fakeHex builds a test key with hex-like zeros at runtime.
func fakeHex(prefix string, n int) string {
	return prefix + strings.Repeat("0", n)
}

func TestContainsSecrets(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{name: "no secret", text: "I prefer Go over Python", want: false},
		{name: "empty", text: "", want: false},
		{name: "openai key", text: "my key is sk-abcdefghijklmnopqrstuvwxyz1234567890", want: true},
		{name: "anthropic key", text: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz", want: true},
		{name: "google api key", text: "AIzaSyBcdefghijklmnopqrstuvwxyz01234567", want: true},
		{name: "github pat", text: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", want: true},
		{name: "github fine-grained", text: "github_pat_ABCDEFGHIJKLMNOPQRSTUVW", want: true},
		{name: "aws access key", text: "AKIAIOSFODNN7EXAMPLE", want: true},
		{name: "slack token", text: "xoxb-1234567890-abcdefghij", want: true},
		{name: "jwt", text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", want: true},
		{name: "postgres connection", text: "postgres://user:pass@localhost/db", want: true},
		{name: "pem private key", text: "-----BEGIN RSA PRIVATE KEY-----", want: true},
		{name: "bearer token", text: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef", want: true},
		{name: "api_key assignment", text: "api_key = sk_live_1234567890abcdef", want: true},
		{name: "password assignment", text: "password=MyS3cur3P@ss!", want: true},
		// Built at runtime to avoid GitHub secret scanning on source literals.
		{name: "stripe live key", text: fakeKey("sk_"+"live_", 24), want: true},
		{name: "stripe test key", text: fakeKey("sk_"+"test_", 24), want: true},
		{name: "stripe restricted", text: fakeKey("rk_"+"live_", 24), want: true},
		{name: "twilio account sid", text: fakeHex("AC", 32), want: true},
		{name: "twilio api key", text: fakeHex("SK", 32), want: true},
		{name: "normal code", text: "func main() { fmt.Println(\"hello\") }", want: false},
		{name: "short string", text: "go build ./...", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsSecrets(tt.text)
			if got != tt.want {
				t.Errorf("ContainsSecrets(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestSanitizeLines(t *testing.T) {
	input := strings.Join([]string{
		"I like Go programming",
		"my key is sk-abcdefghijklmnopqrstuvwxyz1234567890",
		"I work at Acme Corp",
		"password=hunter2_extra_chars",
	}, "\n")

	got := SanitizeLines(input)

	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("SanitizeLines() line count = %d, want 4", len(lines))
	}

	if lines[0] != "I like Go programming" {
		t.Errorf("SanitizeLines() line 0 = %q, want %q", lines[0], "I like Go programming")
	}
	if lines[1] != RedactedPlaceholder {
		t.Errorf("SanitizeLines() line 1 = %q, want %q", lines[1], RedactedPlaceholder)
	}
	if lines[2] != "I work at Acme Corp" {
		t.Errorf("SanitizeLines() line 2 = %q, want %q", lines[2], "I work at Acme Corp")
	}
	if lines[3] != RedactedPlaceholder {
		t.Errorf("SanitizeLines() line 3 = %q, want %q", lines[3], RedactedPlaceholder)
	}
}

func TestSanitizeLines_NoSecrets(t *testing.T) {
	input := "line one\nline two\nline three"
	got := SanitizeLines(input)
	if got != input {
		t.Errorf("SanitizeLines() = %q, want unchanged input", got)
	}
}

func TestSanitizeLines_Empty(t *testing.T) {
	got := SanitizeLines("")
	if got != "" {
		t.Errorf("SanitizeLines(\"\") = %q, want empty", got)
	}
}

func FuzzContainsSecrets(f *testing.F) {
	f.Add("hello world")
	f.Add("sk-1234567890abcdefghijklmnop")
	f.Add("")
	f.Add("password=secret123456")
	f.Fuzz(func(_ *testing.T, input string) {
		ContainsSecrets(input) // must not panic
	})
}
