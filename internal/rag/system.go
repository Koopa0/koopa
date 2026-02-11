package rag

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DeleteByIDs deletes documents by their IDs.
// Used for UPSERT emulation since Genkit DocStore only supports INSERT.
// Exported for testing (fuzz tests in rag_test package).
func DeleteByIDs(ctx context.Context, pool *pgxpool.Pool, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	// Use parameterized query to prevent SQL injection
	query := `DELETE FROM documents WHERE id = ANY($1)`
	if _, err := pool.Exec(ctx, query, ids); err != nil {
		return fmt.Errorf("deleting documents: %w", err)
	}
	return nil
}
