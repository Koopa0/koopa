//go:build integration

package rag_test

import (
	"context"
	"strings"
	"testing"

	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/testutil"
)

// FuzzDeleteByIDs_SQLInjection tests that deleteByIDs is safe from SQL injection.
// Uses parameterized queries so malicious input should not cause SQL injection.
func FuzzDeleteByIDs_SQLInjection(f *testing.F) {
	// Seed with known SQL injection attack vectors
	f.Add("'; DROP TABLE documents; --")
	f.Add("1' OR '1'='1")
	f.Add("uuid' UNION SELECT * FROM sessions --")
	f.Add("\x00malicious")
	f.Add("'; SELECT pg_sleep(10); --")
	f.Add("\\'; COPY documents TO '/tmp/pwned'; --")
	f.Add("'; DELETE FROM documents; --")
	f.Add("' OR 1=1--")
	f.Add("admin'--")
	f.Add("1; DROP TABLE users")
	f.Add("' UNION SELECT password FROM users--")

	f.Fuzz(func(t *testing.T, maliciousID string) {
		if maliciousID == "" {
			t.Skip("empty string is valid input")
		}

		// Setup test database
		dbContainer := testutil.SetupTestDB(t)

		ctx := context.Background()
		pool := dbContainer.Pool

		// Attempt deletion with malicious ID - should be safely parameterized
		ids := []string{maliciousID}
		err := rag.DeleteByIDs(ctx, pool, ids)

		// Error is OK (invalid UUID or other DB error), but SQL injection indicators are NOT OK
		if err != nil {
			errMsg := strings.ToLower(err.Error())
			// These indicate SQL injection success - MUST NOT happen
			if strings.Contains(errMsg, "syntax error") ||
				strings.Contains(errMsg, "unterminated") ||
				strings.Contains(errMsg, "drop table") ||
				strings.Contains(errMsg, "union select") {
				t.Fatalf("possible SQL injection! input: %q, error: %v", maliciousID, err)
			}
		}

		// Verify documents table still exists (wasn't dropped)
		var exists bool
		err = pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'documents')").
			Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("documents table destroyed by injection: %q", maliciousID)
		}
	})
}

// TestDeleteByIDs_EmptySlice verifies empty slice input is handled correctly.
func TestDeleteByIDs_EmptySlice(t *testing.T) {
	t.Parallel()

	dbContainer := testutil.SetupTestDB(t)

	ctx := context.Background()

	// Empty slice should return nil without executing query
	err := rag.DeleteByIDs(ctx, dbContainer.Pool, []string{})
	if err != nil {
		t.Errorf("DeleteByIDs(empty slice) unexpected error: %v", err)
	}
}

// TestDeleteByIDs_ValidUUIDs verifies deletion with valid UUIDs works.
func TestDeleteByIDs_ValidUUIDs(t *testing.T) {
	t.Parallel()

	dbContainer := testutil.SetupTestDB(t)

	ctx := context.Background()

	// Valid UUIDs that don't exist should not error
	validIDs := []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
	}

	err := rag.DeleteByIDs(ctx, dbContainer.Pool, validIDs)
	if err != nil {
		t.Errorf("DeleteByIDs(valid UUIDs) unexpected error: %v", err)
	}
}
