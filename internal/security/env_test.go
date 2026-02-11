package security

import (
	"testing"
)

// TestEnvValidator tests environment variable validation with word-boundary matching.
func TestEnvValidator(t *testing.T) {
	envValidator := NewEnv()

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		// Allowed — no sensitive segment
		{name: "generic var", key: "MY_VAR", wantErr: false},
		{name: "HOME", key: "HOME", wantErr: false},
		{name: "SHELL", key: "SHELL", wantErr: false},
		{name: "TERM", key: "TERM", wantErr: false},

		// Word-boundary: previously false positives, now allowed
		{name: "PWD allowed", key: "PWD", wantErr: false},
		{name: "GOPATH allowed", key: "GOPATH", wantErr: false},
		{name: "MANPATH allowed", key: "MANPATH", wantErr: false},
		{name: "PYTHONPATH allowed", key: "PYTHONPATH", wantErr: false},

		// Blocked — exact match
		{name: "API_KEY blocked", key: "API_KEY", wantErr: true},
		{name: "PASSWORD blocked", key: "PASSWORD", wantErr: true},
		{name: "SECRET blocked", key: "SECRET", wantErr: true},
		{name: "TOKEN blocked", key: "TOKEN", wantErr: true},
		{name: "DATABASE_URL blocked", key: "DATABASE_URL", wantErr: true},

		// Blocked — segment match
		{name: "DB_PASSWORD blocked", key: "DB_PASSWORD", wantErr: true},
		{name: "MY_API_KEY blocked", key: "MY_API_KEY", wantErr: true},
		{name: "MY_SECRET_KEY blocked", key: "MY_SECRET_KEY", wantErr: true},
		{name: "APP_TOKEN blocked", key: "APP_TOKEN", wantErr: true},

		// Cloud provider segment matching
		{name: "AZURE_CLIENT_ID blocked", key: "AZURE_CLIENT_ID", wantErr: true},
		{name: "AZURE_TENANT_ID blocked", key: "AZURE_TENANT_ID", wantErr: true},
		{name: "GCP_PROJECT blocked", key: "GCP_PROJECT", wantErr: true},
		{name: "GCP_REGION blocked", key: "GCP_REGION", wantErr: true},

		// Case insensitive
		{name: "lowercase password blocked", key: "db_password", wantErr: true},
		{name: "mixed case api_key blocked", key: "My_Api_Key", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := envValidator.Validate(tt.key)
			if tt.wantErr && err == nil {
				t.Errorf("Validate(%q) = nil, want error", tt.key)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tt.key, err)
			}
		})
	}
}

// TestIsSensitivePattern tests the word-boundary matching logic directly.
func TestIsSensitivePattern(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		pattern string
		want    bool
	}{
		// Single-word patterns: word-boundary matching
		{name: "exact match", envName: "PASSWORD", pattern: "PASSWORD", want: true},
		{name: "segment match", envName: "DB_PASSWORD", pattern: "PASSWORD", want: true},
		{name: "no match substring", envName: "PWD", pattern: "PASSWORD", want: false},
		{name: "no match compound", envName: "GOPATH", pattern: "PATH", want: false},
		{name: "segment at start", envName: "SECRET_KEY", pattern: "SECRET", want: true},
		{name: "segment at end", envName: "MY_TOKEN", pattern: "TOKEN", want: true},
		{name: "segment in middle", envName: "MY_SECRET_KEY", pattern: "SECRET", want: true},
		{name: "no partial segment", envName: "MYPASSWORD", pattern: "PASSWORD", want: false},

		// Composite patterns: substring matching
		{name: "composite exact", envName: "API_KEY", pattern: "API_KEY", want: true},
		{name: "composite prefix", envName: "MY_API_KEY", pattern: "API_KEY", want: true},
		{name: "composite suffix", envName: "API_KEY_OLD", pattern: "API_KEY", want: true},
		{name: "composite in middle", envName: "MY_API_KEY_OLD", pattern: "API_KEY", want: true},
		{name: "composite no match", envName: "APIKEY", pattern: "API_KEY", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitivePattern(tt.envName, tt.pattern)
			if got != tt.want {
				t.Errorf("isSensitivePattern(%q, %q) = %v, want %v", tt.envName, tt.pattern, got, tt.want)
			}
		})
	}
}
