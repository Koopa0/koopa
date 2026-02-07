package security

import (
	"testing"
)

// TestEnvValidator tests environment variable validation
func TestEnvValidator(t *testing.T) {
	envValidator := NewEnv()

	tests := []struct {
		name      string
		key       string
		shouldErr bool
		reason    string
	}{
		{
			name:      "valid env key",
			key:       "MY_VAR",
			shouldErr: false,
			reason:    "valid env key should be allowed",
		},
		{
			name:      "API_KEY should be blocked",
			key:       "API_KEY",
			shouldErr: true,
			reason:    "API_KEY is sensitive and should be blocked",
		},
		{
			name:      "PASSWORD should be blocked",
			key:       "PASSWORD",
			shouldErr: true,
			reason:    "PASSWORD is sensitive and should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := envValidator.ValidateEnvAccess(tt.key)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %q, but got none: %s", tt.key, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %q: %v (%s)", tt.key, err, tt.reason)
			}
		})
	}
}
