//go:build integration
// +build integration

package testutil

import (
	"context"
	"testing"
)

// TestSetupTestDB_Integration verifies that SetupTestDB creates a fully functional
// PostgreSQL container with pgvector extension and required schema.
//
// This test validates the test infrastructure itself, ensuring:
//   - Docker container starts successfully
//   - PostgreSQL is accessible
//   - pgvector extension is installed
//   - Database migrations run successfully
//   - All required tables are created
//
// Run with: go test -tags=integration ./internal/testutil -v
func TestSetupTestDB_Integration(t *testing.T) {
	// Setup test database
	dbContainer := SetupTestDB(t)

	// Verify database is accessible
	ctx := context.Background()
	err := dbContainer.Pool.Ping(ctx)
	if err != nil {
		t.Fatalf("Pool.Ping() unexpected error: %v", err)
	}

	// Verify pgvector extension is installed
	var hasExtension bool
	err = dbContainer.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')").Scan(&hasExtension)
	if err != nil {
		t.Fatalf("QueryRow(vector extension check) unexpected error: %v", err)
	}

	if !hasExtension {
		t.Error("pgvector extension installed = false, want true")
	}

	// Verify all required tables exist
	tables := []string{"documents", "sessions", "messages"}
	for _, table := range tables {
		var exists bool
		err = dbContainer.Pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table).Scan(&exists)
		if err != nil {
			t.Fatalf("QueryRow(table %q check) unexpected error: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q exists = false, want true", table)
		}
	}
}
