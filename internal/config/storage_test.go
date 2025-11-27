package config

import (
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
