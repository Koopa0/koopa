package agent

import (
	"context"
	"testing"
)

// TestSetupTestDB_Integration demonstrates using SetupTestDB helper
func TestSetupTestDB_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

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

	// Verify tables exist
	tables := []string{"documents", "sessions", "messages"}
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

// TestSetupTestAgent_Integration demonstrates using SetupTestAgent helper
func TestSetupTestAgent_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Setup test agent framework
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	// Verify agent is created
	if framework.Agent == nil {
		t.Fatal("Agent not created")
	}

	// Verify session exists
	ctx := context.Background()
	session, err := framework.SessionStore.GetSession(ctx, framework.SessionID)
	if err != nil {
		t.Fatalf("Failed to get test session: %v", err)
	}

	if session.Title != "Integration Test Session" {
		t.Errorf("Expected session title 'Integration Test Session', got %q", session.Title)
	}

	t.Logf("Agent framework created successfully with session %s", framework.SessionID)
}
