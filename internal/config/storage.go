package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// quoteDSNValue quotes a value for PostgreSQL key=value DSN format.
// Within single quotes, backslashes and single quotes are escaped.
// This prevents parsing errors when values contain spaces or special characters.
func quoteDSNValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// PostgresConnectionString returns the PostgreSQL DSN for pgx driver.
// Password is single-quoted to handle special characters (spaces, =, quotes).
func (c *Config) PostgresConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresUser,
		quoteDSNValue(c.PostgresPassword),
		c.PostgresDBName,
		c.PostgresSSLMode,
	)
}

// PostgresURL returns the PostgreSQL URL for golang-migrate.
// Uses url.URL for proper encoding of special characters in credentials.
func (c *Config) PostgresURL() string {
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.PostgresUser, c.PostgresPassword),
		Host:     fmt.Sprintf("%s:%d", c.PostgresHost, c.PostgresPort),
		Path:     c.PostgresDBName,
		RawQuery: fmt.Sprintf("sslmode=%s", c.PostgresSSLMode),
	}
	return u.String()
}

// parseDatabaseURL parses DATABASE_URL environment variable and sets PostgreSQL config.
// Format: postgres://user:password@host:port/database?sslmode=disable
//
// Priority: DATABASE_URL overrides individual postgres_* settings.
// This provides a simpler configuration option commonly used in cloud deployments.
func (c *Config) parseDatabaseURL() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil // No DATABASE_URL set, use individual config values
	}

	parsed, err := url.Parse(dbURL)
	if err != nil {
		return fmt.Errorf("invalid DATABASE_URL format: %w", err)
	}

	// Validate scheme
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("DATABASE_URL must start with postgres:// or postgresql://, got %q", parsed.Scheme)
	}

	// Extract host and port
	host := parsed.Hostname()
	if host != "" {
		c.PostgresHost = host
	}

	portStr := parsed.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port in DATABASE_URL: %w", err)
		}
		c.PostgresPort = port
	}

	// Extract user and password
	if parsed.User != nil {
		if user := parsed.User.Username(); user != "" {
			c.PostgresUser = user
		}
		if password, ok := parsed.User.Password(); ok {
			c.PostgresPassword = password
		}
	}

	// Extract database name (path without leading /)
	if parsed.Path != "" {
		c.PostgresDBName = strings.TrimPrefix(parsed.Path, "/")
	}

	// Extract sslmode from query params
	if sslmode := parsed.Query().Get("sslmode"); sslmode != "" {
		c.PostgresSSLMode = sslmode
	}

	return nil
}
