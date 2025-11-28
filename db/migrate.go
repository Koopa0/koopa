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
		slog.Error("failed to create migration source", "error", err)
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	// Convert postgres:// or postgresql:// to pgx5:// scheme for golang-migrate pgx v5 driver
	dbURL, err := convertToMigrateURL(connURL)
	if err != nil {
		slog.Error("invalid database URL", "error", err)
		return err
	}

	// Create migrate instance with pgx5 driver
	m, err := migrate.NewWithSourceInstance("iofs", source, dbURL)
	if err != nil {
		slog.Error("failed to connect to database for migrations", "error", err)
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			slog.Warn("failed to close migration source", "error", srcErr)
		}
		if dbErr != nil {
			slog.Warn("failed to close migration database connection", "error", dbErr)
		}
	}()

	// Check for dirty state before running migrations
	version, dirty, verErr := m.Version()
	if verErr != nil && !errors.Is(verErr, migrate.ErrNilVersion) {
		slog.Error("failed to check migration version", "error", verErr)
		return fmt.Errorf("failed to check migration version: %w", verErr)
	}
	if dirty {
		slog.Error("database is in dirty migration state - manual intervention required",
			"version", version,
			"hint", fmt.Sprintf("inspect schema and run: migrate force %d", version))
		return fmt.Errorf("database in dirty state (version=%d), manual cleanup required", version)
	}

	// Run migrations
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Debug("no new migrations to apply")
			return nil
		}

		// Check for dirty state after failure
		postVersion, postDirty, postErr := m.Version()
		if postErr == nil && postDirty {
			slog.Error("migration failed - database now in dirty state",
				"version", postVersion,
				"hint", fmt.Sprintf("fix the migration and run: migrate force %d", postVersion))
		}

		slog.Error("failed to run migrations", "error", err)
		return fmt.Errorf("failed to run migrations: %w", err)
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
		return "", fmt.Errorf("failed to parse database URL: %w", err)
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
