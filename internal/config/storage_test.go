package config

import (
	"os"
	"strings"
	"testing"
)

// TestPostgresConnectionString tests DSN generation
func TestPostgresConnectionString(t *testing.T) {
	cfg := &Config{
		PostgresHost:     "test-host",
		PostgresPort:     5433,
		PostgresUser:     "test-user",
		PostgresPassword: "test-password",
		PostgresDBName:   "test-db",
		PostgresSSLMode:  "require",
	}

	dsn := cfg.PostgresConnectionString()

	expectedParts := []string{
		"host=test-host",
		"port=5433",
		"user=test-user",
		"password=test-password",
		"dbname=test-db",
		"sslmode=require",
	}

	for _, part := range expectedParts {
		if !strings.Contains(dsn, part) {
			t.Errorf("DSN should contain %q, got: %s", part, dsn)
		}
	}
}

// TestPostgresURL tests PostgreSQL URL generation for golang-migrate
func TestPostgresURL(t *testing.T) {
	cfg := &Config{
		PostgresHost:     "test-host",
		PostgresPort:     5433,
		PostgresUser:     "test-user",
		PostgresPassword: "test-password",
		PostgresDBName:   "test-db",
		PostgresSSLMode:  "require",
	}

	url := cfg.PostgresURL()

	expected := "postgres://test-user:test-password@test-host:5433/test-db?sslmode=require"
	if url != expected {
		t.Errorf("PostgresURL() = %q, want %q", url, expected)
	}
}

// TestParseDatabaseURL tests DATABASE_URL parsing
func TestParseDatabaseURL(t *testing.T) {
	tests := []struct {
		name     string
		dbURL    string
		wantHost string
		wantPort int
		wantUser string
		wantPass string
		wantDB   string
		wantSSL  string
		wantErr  bool
	}{
		{
			name:     "full URL",
			dbURL:    "postgres://myuser:mypass@myhost:5433/mydb?sslmode=require",
			wantHost: "myhost",
			wantPort: 5433,
			wantUser: "myuser",
			wantPass: "mypass",
			wantDB:   "mydb",
			wantSSL:  "require",
		},
		{
			name:     "minimal URL",
			dbURL:    "postgres://localhost/testdb?sslmode=disable",
			wantHost: "localhost",
			wantPort: 0,  // not specified, keeps default
			wantUser: "", // not specified
			wantPass: "", // not specified
			wantDB:   "testdb",
			wantSSL:  "disable",
		},
		{
			name:     "postgresql scheme",
			dbURL:    "postgresql://user:pass@host:5432/db?sslmode=verify-full",
			wantHost: "host",
			wantPort: 5432,
			wantUser: "user",
			wantPass: "pass",
			wantDB:   "db",
			wantSSL:  "verify-full",
		},
		{
			name:    "invalid scheme",
			dbURL:   "mysql://localhost/db",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			dbURL:   "not a url at all ::::",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			oldVal := os.Getenv("DATABASE_URL")
			_ = os.Setenv("DATABASE_URL", tt.dbURL)
			defer func() { _ = os.Setenv("DATABASE_URL", oldVal) }()

			// Create config with defaults
			cfg := &Config{
				PostgresHost:    "default-host",
				PostgresPort:    5432,
				PostgresUser:    "default-user",
				PostgresSSLMode: "disable",
			}

			err := cfg.parseDatabaseURL()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantHost != "" && cfg.PostgresHost != tt.wantHost {
				t.Errorf("host = %q, want %q", cfg.PostgresHost, tt.wantHost)
			}
			if tt.wantPort != 0 && cfg.PostgresPort != tt.wantPort {
				t.Errorf("port = %d, want %d", cfg.PostgresPort, tt.wantPort)
			}
			if tt.wantUser != "" && cfg.PostgresUser != tt.wantUser {
				t.Errorf("user = %q, want %q", cfg.PostgresUser, tt.wantUser)
			}
			if tt.wantPass != "" && cfg.PostgresPassword != tt.wantPass {
				t.Errorf("password = %q, want %q", cfg.PostgresPassword, tt.wantPass)
			}
			if tt.wantDB != "" && cfg.PostgresDBName != tt.wantDB {
				t.Errorf("dbname = %q, want %q", cfg.PostgresDBName, tt.wantDB)
			}
			if tt.wantSSL != "" && cfg.PostgresSSLMode != tt.wantSSL {
				t.Errorf("sslmode = %q, want %q", cfg.PostgresSSLMode, tt.wantSSL)
			}
		})
	}
}

// TestParseDatabaseURL_Empty tests that empty DATABASE_URL is ignored
func TestParseDatabaseURL_Empty(t *testing.T) {
	oldVal := os.Getenv("DATABASE_URL")
	os.Unsetenv("DATABASE_URL")
	defer os.Setenv("DATABASE_URL", oldVal)

	cfg := &Config{
		PostgresHost: "original-host",
		PostgresPort: 9999,
	}

	err := cfg.parseDatabaseURL()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should keep original values
	if cfg.PostgresHost != "original-host" {
		t.Errorf("host should remain %q, got %q", "original-host", cfg.PostgresHost)
	}
	if cfg.PostgresPort != 9999 {
		t.Errorf("port should remain %d, got %d", 9999, cfg.PostgresPort)
	}
}
