// Package testdb provides a shared PostgreSQL testcontainer for integration tests.
// It starts a pgvector-enabled PostgreSQL container, applies real migrations,
// and returns a connection pool. Use with //go:build integration tests only.
package testdb

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// NewPool starts a pgvector PostgreSQL container, applies all migrations from
// the project's migrations/ directory, and returns a pgxpool.Pool.
// The container is automatically terminated when the test completes.
func NewPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"pgvector/pgvector:pg17",
		postgres.WithDatabase("test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := pgContainer.Terminate(context.Background()); termErr != nil {
			t.Logf("terminating postgres container: %v", termErr)
		}
	})

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting connection string: %v", err)
	}

	runMigrations(t, connStr)

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool
}

// Truncate removes all data from the given tables (in order).
// Use between tests to ensure isolation without recreating the container.
func Truncate(t *testing.T, pool *pgxpool.Pool, tables ...string) {
	t.Helper()
	for _, table := range tables {
		if _, err := pool.Exec(t.Context(), "TRUNCATE "+table+" CASCADE"); err != nil {
			t.Fatalf("truncating %s: %v", table, err)
		}
	}
}

// StartPool is for use in TestMain where *testing.T is not available.
// Returns pool + cleanup function. Call cleanup after m.Run().
//
//	var testPool *pgxpool.Pool
//	func TestMain(m *testing.M) {
//	    testPool, cleanup := testdb.StartPool()
//	    code := m.Run()
//	    cleanup()
//	    os.Exit(code)
//	}
func StartPool() (pool *pgxpool.Pool, cleanup func()) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"pgvector/pgvector:pg17",
		postgres.WithDatabase("test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("testdb: starting postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("testdb: getting connection string: %v", err)
	}

	applyMigrations(connStr)

	pool, err = pgxpool.New(ctx, connStr)
	if err != nil {
		log.Fatalf("testdb: creating pool: %v", err)
	}

	cleanup = func() {
		pool.Close()
		if err := pgContainer.Terminate(ctx); err != nil {
			log.Printf("testdb: terminating container: %v", err)
		}
	}
	return pool, cleanup
}

// applyMigrations runs all migrations from the project's migrations/ directory.
func applyMigrations(connStr string) {
	_, thisFile, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")

	m, err := migrate.New("file://"+migrationsDir, "pgx5://"+connStr[len("postgres://"):])
	if err != nil {
		log.Fatalf("testdb: creating migrator: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("testdb: running migrations: %v", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		log.Fatalf("testdb: closing migration source: %v", srcErr)
	}
	if dbErr != nil {
		log.Fatalf("testdb: closing migration db: %v", dbErr)
	}
}

// TruncateCtx removes all data from the given tables using a context.
// For use when *testing.T is not available.
func TruncateCtx(ctx context.Context, pool *pgxpool.Pool, tables ...string) error {
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE "+table+" CASCADE"); err != nil {
			return fmt.Errorf("truncating %s: %w", table, err)
		}
	}
	return nil
}

func runMigrations(t *testing.T, connStr string) {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")

	m, err := migrate.New("file://"+migrationsDir, "pgx5://"+connStr[len("postgres://"):])
	if err != nil {
		t.Fatalf("creating migrator: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("running migrations: %v", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		t.Fatalf("closing migration source: %v", srcErr)
	}
	if dbErr != nil {
		t.Fatalf("closing migration db: %v", dbErr)
	}
}
