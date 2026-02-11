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
		"password='test-password'",
		"dbname=test-db",
		"sslmode=require",
	}

	for _, part := range expectedParts {
		if !strings.Contains(dsn, part) {
			t.Errorf("DSN should contain %q, got: %s", part, dsn)
		}
	}
}

// TestPostgresConnectionStringSpecialChars tests DSN quoting handles special characters.
// The password is single-quoted in DSN format, so injection payloads like
// "' host=evil.com" become part of the quoted value, not separate DSN keys.
func TestPostgresConnectionStringSpecialChars(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		wantQuoted string // expected quoted form in DSN
	}{
		{
			name:       "password with spaces",
			password:   "my secret pass",
			wantQuoted: "'my secret pass'",
		},
		{
			name:       "password with single quotes",
			password:   "pass'word",
			wantQuoted: `'pass\'word'`,
		},
		{
			name:       "DSN injection attempt",
			password:   "' host=evil.com user=hacker password='",
			wantQuoted: `'\' host=evil.com user=hacker password=\''`,
		},
		{
			name:       "password with backslash",
			password:   `pass\word`,
			wantQuoted: `'pass\\word'`,
		},
		{
			name:       "password with equals",
			password:   "pass=word",
			wantQuoted: "'pass=word'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresUser:     "user",
				PostgresPassword: tt.password,
				PostgresDBName:   "db",
				PostgresSSLMode:  "disable",
			}
			dsn := cfg.PostgresConnectionString()

			// Verify password is correctly quoted in DSN
			wantPart := "password=" + tt.wantQuoted
			if !strings.Contains(dsn, wantPart) {
				t.Errorf("PostgresConnectionString() missing %q\ngot: %s", wantPart, dsn)
			}

			// Verify DSN ends with expected structure after password
			if !strings.HasSuffix(dsn, "dbname=db sslmode=disable") {
				t.Errorf("PostgresConnectionString() has corrupted suffix\ngot: %s", dsn)
			}
		})
	}
}

// TestQuoteDSNValue tests the DSN value quoting helper.
func TestQuoteDSNValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "simple", want: "'simple'"},
		{input: "with space", want: "'with space'"},
		{input: "with'quote", want: `'with\'quote'`},
		{input: `with\backslash`, want: `'with\\backslash'`},
		{input: "", want: "''"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := quoteDSNValue(tt.input)
			if got != tt.want {
				t.Errorf("quoteDSNValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestPostgresURL tests PostgreSQL URL generation for golang-migrate
func TestPostgresURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "simple credentials",
			cfg: &Config{
				PostgresHost:     "test-host",
				PostgresPort:     5433,
				PostgresUser:     "test-user",
				PostgresPassword: "test-password",
				PostgresDBName:   "test-db",
				PostgresSSLMode:  "require",
			},
			want: "postgres://test-user:test-password@test-host:5433/test-db?sslmode=require",
		},
		{
			name: "password with special characters",
			cfg: &Config{
				PostgresHost:     "localhost",
				PostgresPort:     5432,
				PostgresUser:     "koopa",
				PostgresPassword: "p@ss/word#123",
				PostgresDBName:   "koopa",
				PostgresSSLMode:  "disable",
			},
			want: "postgres://koopa:p%40ss%2Fword%23123@localhost:5432/koopa?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.PostgresURL()
			if got != tt.want {
				t.Errorf("PostgresURL() = %q, want %q", got, tt.want)
			}
		})
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
