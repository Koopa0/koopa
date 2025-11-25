// Package testutil provides shared testing utilities for the koopa project.
//
// This package contains reusable test infrastructure that can be used across
// multiple packages, following the pattern of Go standard library packages
// like net/http/httptest and testing/iotest.
package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDBContainer wraps a PostgreSQL test container with connection pool.
//
// Provides:
//   - Isolated PostgreSQL instance with pgvector extension
//   - Connection pool for database operations
//   - Automatic cleanup via cleanup function
//
// Usage:
//
//	db, cleanup := testutil.SetupTestDB(t)
//	defer cleanup()
//	// Use db.Pool for database operations
type TestDBContainer struct {
	Container *postgres.PostgresContainer
	Pool      *pgxpool.Pool
	ConnStr   string
}

// SetupTestDB creates a PostgreSQL container for testing with pgvector extension.
//
// Creates a fully-configured PostgreSQL container with:
//   - pgvector extension (for vector similarity search)
//   - Test database schema (via migrations)
//   - Connection pool ready for use
//
// Returns:
//   - TestDBContainer: Container with connection pool
//   - cleanup function: Must be called to terminate container
//
// Example:
//
//	func TestMyFeature(t *testing.T) {
//	    db, cleanup := testutil.SetupTestDB(t)
//	    defer cleanup()
//
//	    // Use db.Pool for queries
//	    var count int
//	    err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM documents").Scan(&count)
//	    require.NoError(t, err)
//	}
func SetupTestDB(t *testing.T) (*TestDBContainer, func()) {
	t.Helper()

	ctx := context.Background()

	// Create PostgreSQL container with pgvector support
	pgContainer, err := postgres.Run(ctx,
		"pgvector/pgvector:pg16",
		postgres.WithDatabase("koopa_test"),
		postgres.WithUsername("koopa_test"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Create connection pool
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create connection pool: %v", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Run migrations
	if err := runMigrations(ctx, pool); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	container := &TestDBContainer{
		Container: pgContainer,
		Pool:      pool,
		ConnStr:   connStr,
	}

	cleanup := func() {
		if pool != nil {
			pool.Close()
		}
		if pgContainer != nil {
			_ = pgContainer.Terminate(context.Background())
		}
	}

	return container, cleanup
}

// findProjectRoot finds the project root directory by looking for go.mod.
// This allows tests to run from any subdirectory and still find migration files.
func findProjectRoot() (string, error) {
	// Start from the current file's directory
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get current file path")
	}

	dir := filepath.Dir(filename)

	// Walk up the directory tree until we find go.mod
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding go.mod
			return "", fmt.Errorf("could not find project root (go.mod)")
		}
		dir = parent
	}
}

// runMigrations runs database migrations from db/migrations directory.
//
// Executes migrations in order:
//  1. 000001_init_schema.up.sql - Creates tables and pgvector extension
//  2. 000002_create_sessions.up.sql - Creates session tables
//
// Each migration runs in its own transaction for atomicity.
// This is a simplified version - production should use a migration tool like golang-migrate.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Find project root to build absolute paths to migrations
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Read and execute migration files in order
	migrationFiles := []string{
		filepath.Join(projectRoot, "db/migrations/000001_init_schema.up.sql"),
		filepath.Join(projectRoot, "db/migrations/000002_create_sessions.up.sql"),
	}

	for _, migrationPath := range migrationFiles {
		// #nosec G304 -- migration paths are hardcoded constants, not from user input
		migrationSQL, err := os.ReadFile(migrationPath)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", migrationPath, err)
		}

		// Skip empty migration files to avoid unnecessary execution
		if len(migrationSQL) == 0 {
			continue
		}

		// Execute each migration in its own transaction using an anonymous function
		// This ensures defer executes at the end of each iteration, not at function end
		err = func() error {
			// Wrap migration execution in a transaction for atomicity
			// This ensures that if a migration fails, changes are rolled back
			tx, err := pool.Begin(ctx)
			if err != nil {
				return fmt.Errorf("failed to begin transaction for migration %s: %w", migrationPath, err)
			}

			// Ensure transaction is always closed (rollback unless committed)
			// This protects against panics and ensures proper resource cleanup
			committed := false
			defer func() {
				if !committed {
					if err := tx.Rollback(ctx); err != nil {
						slog.Default().Debug("migration transaction rollback (may be already committed)",
							"migration", migrationPath, "error", err)
					}
				}
			}()

			_, err = tx.Exec(ctx, string(migrationSQL))
			if err != nil {
				return fmt.Errorf("failed to execute migration %s: %w", migrationPath, err)
			}

			if err = tx.Commit(ctx); err != nil {
				return fmt.Errorf("failed to commit migration %s: %w", migrationPath, err)
			}
			committed = true
			return nil
		}()

		if err != nil {
			return err
		}
	}

	return nil
}
