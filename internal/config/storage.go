package config

import "fmt"

// StorageConfig documentation.
// Fields are embedded in the main Config struct for backward compatibility.
//
// SQLite:
//   - DatabasePath: Path to SQLite database file
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
