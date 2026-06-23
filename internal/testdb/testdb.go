// Copyright 2026 Koopa. All rights reserved.

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
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// NewPool starts a pgvector PostgreSQL container, applies all migrations, and
// returns the pool plus a cleanup function. It uses log.Fatal rather than
// *testing.T so it can run from TestMain (where no *testing.T exists); call
// cleanup after m.Run().
//
//	var testPool *pgxpool.Pool
//	func TestMain(m *testing.M) {
//	    testPool, cleanup := testdb.NewPool()
//	    code := m.Run()
//	    cleanup()
//	    os.Exit(code)
//	}
func NewPool() (pool *pgxpool.Pool, cleanup func()) {
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
