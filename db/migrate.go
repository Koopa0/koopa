// Package db provides database utilities including migration support.
package db

import (
	"embed"
	"errors"
	"log/slog"

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
// connURL must be in postgres:// URL format (e.g., postgres://user:pass@host:port/db?sslmode=disable)
func Migrate(connURL string) error {
	slog.Info("running database migrations")

	// Create source driver from embedded filesystem
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		slog.Error("failed to create migration source", "error", err)
		return err
	}

	// Create migrate instance with pgx5 driver
	// Convert postgres:// to pgx5:// scheme for golang-migrate pgx v5 driver
	dbURL := "pgx5" + connURL[len("postgres"):]
	m, err := migrate.NewWithSourceInstance("iofs", source, dbURL)
	if err != nil {
		slog.Error("failed to connect to database for migrations", "error", err)
		return err
	}
	defer m.Close()

	// Run migrations
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("no new migrations to apply")
			return nil
		}
		slog.Error("failed to run migrations", "error", err)
		return err
	}

	version, dirty, err := m.Version()
	if err != nil {
		slog.Info("migrations completed")
	} else {
		slog.Info("migrations completed", "version", version, "dirty", dirty)
	}

	return nil
}
