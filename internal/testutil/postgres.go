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
//   - Automatic cleanup via tb.Cleanup (no manual cleanup needed)
//
// Usage:
//
//	db := testutil.SetupTestDB(t)
//	// Use db.Pool for database operations
type TestDBContainer struct {
	container *postgres.PostgresContainer
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
// Cleanup is registered via tb.Cleanup and runs automatically when the test ends.
//
// Example:
//
//	func TestMyFeature(t *testing.T) {
//	    db := testutil.SetupTestDB(t)
//
//	    // Use db.Pool for queries
//	    var count int
//	    err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM documents").Scan(&count)
//	    if err != nil {
//	        t.Fatalf("QueryRow() unexpected error: %v", err)
//	    }
//	}
//
// Note: Accepts testing.TB interface to support both *testing.T (tests) and
// *testing.B (benchmarks). This allows the same setup to be used in both contexts.
func SetupTestDB(tb testing.TB) *TestDBContainer {
	tb.Helper()

	container, cleanup, err := startTestDB()
	if err != nil {
		tb.Fatalf("starting test database: %v", err)
	}
	tb.Cleanup(cleanup)
	return container
}

// SetupTestDBForMain creates a PostgreSQL container for use in TestMain.
//
// Unlike SetupTestDB, it does not register cleanup via tb.Cleanup.
// The caller must call the returned cleanup function after m.Run().
//
// Use this when multiple tests in a package share a single container
// to reduce Docker resource usage. Use CleanTables between tests for isolation.
//
// Example:
//
//	var sharedDB *testutil.TestDBContainer
//
//	func TestMain(m *testing.M) {
//	    var cleanup func()
//	    var err error
//	    sharedDB, cleanup, err = testutil.SetupTestDBForMain()
//	    if err != nil {
//	        log.Fatalf("starting test database: %v", err)
//	    }
//	    code := m.Run()
//	    cleanup()
//	    os.Exit(code)
//	}
func SetupTestDBForMain() (*TestDBContainer, func(), error) {
	return startTestDB()
}

// startTestDB creates a PostgreSQL container with pgvector, runs migrations,
// and returns the container, a cleanup function, and any error.
func startTestDB() (*TestDBContainer, func(), error) {
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
		return nil, nil, fmt.Errorf("starting PostgreSQL container: %w", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx) // best-effort cleanup
		return nil, nil, fmt.Errorf("getting connection string: %w", err)
	}

	// Create connection pool
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx) // best-effort cleanup
		return nil, nil, fmt.Errorf("creating connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx) // best-effort cleanup
		return nil, nil, fmt.Errorf("pinging database: %w", err)
	}

	// Run migrations
	if err := runMigrations(ctx, pool); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("running migrations: %w", err)
	}

	container := &TestDBContainer{
		container: pgContainer,
		Pool:      pool,
		ConnStr:   connStr,
	}

	cleanup := func() {
		pool.Close()
		_ = pgContainer.Terminate(context.Background())
	}

	return container, cleanup, nil
}

// CleanTables truncates all test tables between tests for isolation.
//
// Call this at the start of each test when using shared containers via TestMain.
// Uses TRUNCATE CASCADE to handle foreign key relationships.
func CleanTables(tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	ctx := context.Background()
	// TRUNCATE with CASCADE handles FK dependencies (messages→sessions, memories→sessions)
	_, err := pool.Exec(ctx, "TRUNCATE memories, messages, documents, sessions CASCADE")
	if err != nil {
		tb.Fatalf("truncating tables: %v", err)
	}
}

// FindProjectRoot finds the project root directory by looking for go.mod.
// This allows tests to run from any subdirectory and still find migration files.
func FindProjectRoot() (string, error) {
	// Start from the current file's directory
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("getting current file path")
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
// Executes the consolidated schema migration:
//  1. 000001_init_schema.up.sql - Creates all tables, extensions, and indexes
//
// The schema is consolidated into a single migration file that includes
// sessions (with owner_id), messages, documents (with owner_id and pgvector),
// and memories (with decay, access tracking, tsvector, categories).
//
// Each migration runs in its own transaction for atomicity.
// This is a simplified version - production should use a migration tool like golang-migrate.
//
//nolint:gocognit // Complex error handling necessary for transaction safety in test utility
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Find project root to build absolute paths to migrations
	projectRoot, err := FindProjectRoot()
	if err != nil {
		return fmt.Errorf("finding project root: %w", err)
	}

	// Read and execute migration files in order.
	// Schema is consolidated into a single migration file.
	migrationFiles := []string{
		filepath.Join(projectRoot, "db", "migrations", "000001_init_schema.up.sql"),
	}

	for _, migrationPath := range migrationFiles {
		// #nosec G304 -- migration paths are hardcoded constants, not from user input
		migrationSQL, readErr := os.ReadFile(migrationPath)
		if readErr != nil {
			return fmt.Errorf("reading migration %s: %w", migrationPath, readErr)
		}

		// Skip empty migration files to avoid unnecessary execution
		if len(migrationSQL) == 0 {
			continue
		}

		// Execute each migration in its own transaction using an anonymous function
		// This ensures defer executes at the end of each iteration, not at function end
		migErr := func() error {
			// Wrap migration execution in a transaction for atomicity
			// This ensures that if a migration fails, changes are rolled back
			tx, beginErr := pool.Begin(ctx)
			if beginErr != nil {
				return fmt.Errorf("beginning transaction for migration %s: %w", migrationPath, beginErr)
			}

			// Ensure transaction is always closed (rollback unless committed)
			// This protects against panics and ensures proper resource cleanup
			committed := false
			defer func() {
				if !committed {
					if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
						slog.Default().Debug("migration transaction rollback (may be already committed)",
							"migration", migrationPath, "error", rollbackErr)
					}
				}
			}()

			_, execErr := tx.Exec(ctx, string(migrationSQL))
			if execErr != nil {
				return fmt.Errorf("executing migration %s: %w", migrationPath, execErr)
			}

			if commitErr := tx.Commit(ctx); commitErr != nil {
				return fmt.Errorf("committing migration %s: %w", migrationPath, commitErr)
			}
			committed = true
			return nil
		}()

		if migErr != nil {
			return migErr
		}
	}

	return nil
}
