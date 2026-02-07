package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// StorageConfig documentation.
// Fields are embedded in the main Config struct for backward compatibility.
//
// PostgreSQL (for pgvector):
//   - PostgresHost: Database host (default: localhost)
//   - PostgresPort: Database port (default: 5432)
//   - PostgresUser: Database user (default: koopa)
//   - PostgresPassword: Database password
//   - PostgresDBName: Database name (default: koopa)
//   - PostgresSSLMode: SSL mode (default: disable)
//
// RAG:
//   - RAGTopK: Number of documents to retrieve (1-10, default: 3)
//   - EmbedderModel: Embedding model name (default: text-embedding-004)

// PostgresConnectionString returns the PostgreSQL DSN for pgx driver.
func (c *Config) PostgresConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresDBName,
		c.PostgresSSLMode,
	)
}

// PostgresURL returns the PostgreSQL URL for golang-migrate.
func (c *Config) PostgresURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresDBName,
		c.PostgresSSLMode,
	)
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
