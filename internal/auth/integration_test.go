// Copyright 2026 Koopa. All rights reserved.

//go:build integration

package auth_test

import (
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/auth"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// TestStore_DeleteExpiredRefreshTokens proves the cleanup removes only the
// expired rows: an expired token is gone after the sweep while a live token
// survives, and the returned count reflects exactly the deletions. This is the
// cleanup the expires_at index and schema comment promise — ConsumeRefreshToken
// alone deletes only the exact presented token, so expired-but-unconsumed rows
// would otherwise accumulate forever.
func TestStore_DeleteExpiredRefreshTokens(t *testing.T) {
	if err := testdb.TruncateCtx(t.Context(), testPool, "refresh_tokens", "users"); err != nil {
		t.Fatal(err)
	}
	store := auth.NewStore(testPool)
	ctx := t.Context()

	user, err := store.UpsertUserByEmail(ctx, "cleanup@example.com")
	if err != nil {
		t.Fatalf("UpsertUserByEmail() error: %v", err)
	}

	// One token already past expiry, one valid for another hour.
	const expiredHash = "expired-token-hash"
	const liveHash = "live-token-hash"
	if err := store.CreateRefreshToken(ctx, user.ID, expiredHash, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("CreateRefreshToken(expired) error: %v", err)
	}
	if err := store.CreateRefreshToken(ctx, user.ID, liveHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateRefreshToken(live) error: %v", err)
	}

	deleted, err := store.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredRefreshTokens() error: %v", err)
	}
	if deleted != 1 {
		t.Errorf("DeleteExpiredRefreshTokens() deleted = %d, want 1", deleted)
	}

	// The expired token is gone: consuming it now returns ErrNotFound.
	if _, err := store.ConsumeRefreshToken(ctx, expiredHash); err == nil {
		t.Error("ConsumeRefreshToken(expired) succeeded after cleanup, want it removed")
	}
	// The live token survives: consuming it succeeds and yields the right row.
	row, err := store.ConsumeRefreshToken(ctx, liveHash)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken(live) after cleanup error: %v", err)
	}
	if row.TokenHash != liveHash {
		t.Errorf("ConsumeRefreshToken(live) token_hash = %q, want %q", row.TokenHash, liveHash)
	}
}
