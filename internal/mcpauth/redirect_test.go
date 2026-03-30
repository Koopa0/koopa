package mcpauth

import (
	"testing"
)

// TestValidRedirectURI_OpenRedirectBypass tests for open-redirect attacks
// via URL authority confusion. An attacker could register:
//
//	http://localhost:80@evil.com/callback
//
// which starts with "http://localhost:" (passes prefix check) but the
// browser interprets "localhost:80" as the userinfo and connects to evil.com.
func TestValidRedirectURI_OpenRedirectBypass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		// legitimate
		{name: "claude.ai callback", uri: "https://claude.ai/callback", want: true},
		{name: "localhost dev server", uri: "http://localhost:3000/callback", want: true},
		{name: "127.0.0.1 dev", uri: "http://127.0.0.1:8080/callback", want: true},

		// attacks: prefix passes but destination is attacker-controlled
		{name: "authority confusion localhost@evil", uri: "http://localhost:80@evil.com/callback", want: false},
		{name: "authority confusion 127.0.0.1@evil", uri: "http://127.0.0.1:8080@evil.com/steal", want: false},
		{name: "authority confusion claude.ai@evil", uri: "https://claude.ai/@evil.com/phish", want: false},
		{name: "backslash bypass", uri: "https://claude.ai\\@evil.com/steal", want: false},
		{name: "fragment injection", uri: "http://localhost:3000/callback#@evil.com", want: true}, // fragment is client-side, safe

		// other blocked
		{name: "http non-localhost", uri: "http://evil.com/callback", want: false},
		{name: "ftp scheme", uri: "ftp://claude.ai/callback", want: false},
		{name: "javascript scheme", uri: "javascript:alert(1)", want: false},
		{name: "empty string", uri: "", want: false},
		{name: "data URI", uri: "data:text/html,<h1>stolen</h1>", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validRedirectURI(tt.uri)
			if got != tt.want {
				t.Errorf("validRedirectURI(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}
