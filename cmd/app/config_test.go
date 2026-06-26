// Copyright 2026 Koopa. All rights reserved.

package main

import "testing"

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
