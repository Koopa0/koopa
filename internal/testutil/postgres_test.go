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
	dbContainer, cleanup := SetupTestDB(t)
	defer cleanup()

	// Verify database is accessible
	ctx := context.Background()
	err := dbContainer.Pool.Ping(ctx)
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Verify pgvector extension is installed
	var hasExtension bool
	err = dbContainer.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')").Scan(&hasExtension)
	if err != nil {
		t.Fatalf("Failed to check for vector extension: %v", err)
	}

	if !hasExtension {
		t.Error("pgvector extension not installed")
	}

	// Verify all required tables exist
	tables := []string{"documents", "sessions", "session_messages"}
	for _, table := range tables {
		var exists bool
		err = dbContainer.Pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table).Scan(&exists)
		if err != nil {
			t.Fatalf("Failed to check for table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("Table %s does not exist", table)
		}
	}

	t.Log("Database setup successful with all required tables")
}
