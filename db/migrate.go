// Package db provides database utilities including migration support.
package db

import (
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // pgx v5 driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate runs all pending database migrations using golang-migrate.
// Migrations are embedded at compile time and executed in order.
//
// The schema_migrations table is automatically managed by golang-migrate.
// Only migrations not yet applied are executed.
//
// connURL must be in postgres:// or postgresql:// URL format
// (e.g., postgres://user:pass@host:port/db?sslmode=disable)
func Migrate(connURL string) error {
	slog.Debug("running database migrations")

	// Create source driver from embedded filesystem
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	// Convert postgres:// or postgresql:// to pgx5:// scheme for golang-migrate pgx v5 driver
	dbURL, err := convertToMigrateURL(connURL)
	if err != nil {
		return err
	}

	// Create migrate instance with pgx5 driver
	m, err := migrate.NewWithSourceInstance("iofs", source, dbURL)
	if err != nil {
		return fmt.Errorf("creating migrate instance: %w", err)
	}
	// best-effort: close errors are non-fatal during migration teardown
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			slog.Warn("closing migration source", "error", srcErr)
		}
		if dbErr != nil {
			slog.Warn("closing migration database connection", "error", dbErr)
		}
	}()

	// Check for dirty state before running migrations
	version, dirty, verErr := m.Version()
	if verErr != nil && !errors.Is(verErr, migrate.ErrNilVersion) {
		return fmt.Errorf("checking migration version: %w", verErr)
	}
	if dirty {
		return fmt.Errorf("database in dirty state (version=%d): inspect schema and run: migrate force %d", version, version)
	}

	// Run migrations
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Debug("no new migrations to apply")
			return nil
		}

		// Include dirty state info in error if migration left database dirty
		postVersion, postDirty, postErr := m.Version()
		if postErr == nil && postDirty {
			return fmt.Errorf("running migrations (database now dirty at version %d, fix and run: migrate force %d): %w", postVersion, postVersion, err)
		}

		return fmt.Errorf("running migrations: %w", err)
	}

	finalVersion, finalDirty, verErr := m.Version()
	if verErr != nil {
		// Migration succeeded but version check failed - log warning for observability
		slog.Warn("migrations completed but version check failed",
			"error", verErr,
			"hint", "check database manually: SELECT version, dirty FROM schema_migrations")
	} else {
		slog.Info("migrations completed", "version", finalVersion, "dirty", finalDirty)
	}

	return nil
}

// convertToMigrateURL converts a postgres:// or postgresql:// URL to pgx5:// for golang-migrate.
func convertToMigrateURL(connURL string) (string, error) {
	// Parse URL to validate and extract components
	u, err := url.Parse(connURL)
	if err != nil {
		return "", fmt.Errorf("parsing database URL: %w", err)
	}

	// Validate scheme
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
		// Convert to pgx5 scheme
		u.Scheme = "pgx5"
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported database URL scheme: %s (expected postgres or postgresql)", u.Scheme)
	}
}
