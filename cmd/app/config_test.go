// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"reflect"
	"testing"
)

// TestConfigHasNoGeminiCapability locks the owner decision that the app
// server does not perform embedding or knowledge retrieval. Reintroducing a
// provider credential here would recreate that retired runtime dependency.
func TestConfigHasNoGeminiCapability(t *testing.T) {
	typeOfConfig := reflect.TypeFor[config]()
	if field, ok := typeOfConfig.FieldByName("GeminiAPIKey"); ok {
		t.Fatalf("retired Gemini capability remains in app config as field %s", field.Name)
	}
}

func TestValidateOAuth(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{
			name:    "all empty leaves auth disabled",
			cfg:     config{},
			wantErr: false,
		},
		{
			name: "all four set is complete",
			cfg: config{
				GoogleClientID:     "id",
				GoogleClientSecret: "secret",
				GoogleRedirectURI:  "https://koopa0.dev/api/auth/google/callback",
				AdminEmail:         "owner@example.com",
			},
			wantErr: false,
		},
		{
			name:    "client id without admin email boots enabled but rejects every login",
			cfg:     config{GoogleClientID: "id"},
			wantErr: true,
		},
		{
			name: "missing only the redirect uri",
			cfg: config{
				GoogleClientID:     "id",
				GoogleClientSecret: "secret",
				AdminEmail:         "owner@example.com",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOAuth(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOAuth() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
