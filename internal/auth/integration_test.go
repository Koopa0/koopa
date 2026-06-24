// Copyright 2026 Koopa. All rights reserved.

//go:build integration

package auth_test

import (
	"errors"
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

// seedUser truncates the auth tables and returns a fresh user to own tokens.
func seedUser(t *testing.T, store *auth.Store, email string) *auth.User {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool, "refresh_tokens", "users"); err != nil {
		t.Fatal(err)
	}
	user, err := store.UpsertUserByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("UpsertUserByEmail(%q): %v", email, err)
	}
	return user
}

// TestStore_ConsumeRefreshToken_HappyPath proves the create→consume round-trip:
// a freshly created token is consumed exactly once and the returned row carries
// the right user and hash.
func TestStore_ConsumeRefreshToken_HappyPath(t *testing.T) {
	store := auth.NewStore(testPool)
	ctx := t.Context()
	user := seedUser(t, store, "happy@example.com")

	const hash = "happy-token-hash"
	expires := time.Now().Add(time.Hour)
	if err := store.CreateRefreshToken(ctx, user.ID, hash, expires); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	row, err := store.ConsumeRefreshToken(ctx, hash)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken: %v", err)
	}
	if row.UserID != user.ID {
		t.Errorf("consumed token user_id = %v, want %v", row.UserID, user.ID)
	}
	if row.TokenHash != hash {
		t.Errorf("consumed token_hash = %q, want %q", row.TokenHash, hash)
	}
	if row.ExpiresAt.Unix() != expires.Unix() {
		t.Errorf("consumed expires_at = %v, want ~%v", row.ExpiresAt, expires)
	}
}

// TestStore_ConsumeRefreshToken_DoubleConsume proves single-use: the DELETE ...
// RETURNING removes the row on first consume, so a second consume of the same
// hash returns ErrNotFound. This is the property that stops a leaked-then-
// replayed refresh token from minting tokens twice.
func TestStore_ConsumeRefreshToken_DoubleConsume(t *testing.T) {
	store := auth.NewStore(testPool)
	ctx := t.Context()
	user := seedUser(t, store, "double@example.com")

	const hash = "single-use-hash"
	if err := store.CreateRefreshToken(ctx, user.ID, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	if _, err := store.ConsumeRefreshToken(ctx, hash); err != nil {
		t.Fatalf("first ConsumeRefreshToken: %v", err)
	}
	_, err := store.ConsumeRefreshToken(ctx, hash)
	if !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("second ConsumeRefreshToken err = %v, want auth.ErrNotFound", err)
	}
}

// TestStore_ConsumeRefreshToken_Expired proves the store still returns an
// expired-but-unconsumed token (the handler — not the store — enforces expiry
// via ExpiresAt), and that consuming it removes it. The store's contract is
// "return the row if it exists"; this pins that an expired row is returned with
// a past ExpiresAt, so the handler's time check has something to reject.
func TestStore_ConsumeRefreshToken_Expired(t *testing.T) {
	store := auth.NewStore(testPool)
	ctx := t.Context()
	user := seedUser(t, store, "expired@example.com")

	const hash = "expired-hash"
	past := time.Now().Add(-time.Hour)
	if err := store.CreateRefreshToken(ctx, user.ID, hash, past); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	row, err := store.ConsumeRefreshToken(ctx, hash)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken(expired): %v", err)
	}
	if !row.ExpiresAt.Before(time.Now()) {
		t.Errorf("consumed token expires_at = %v, want in the past (so the handler rejects it)", row.ExpiresAt)
	}
	// Consuming it removed the row — a second consume is ErrNotFound.
	if _, err := store.ConsumeRefreshToken(ctx, hash); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("re-consume of expired token err = %v, want auth.ErrNotFound", err)
	}
}

// TestStore_RefreshToken_Rotation models the store half of refresh-token
// rotation the handler performs: consume the presented token (its hash is
// permanently gone) and create a new one (the new hash is now consumable). After
// rotation the OLD hash must not consume, and the NEW hash must consume exactly
// once to the same user.
func TestStore_RefreshToken_Rotation(t *testing.T) {
	store := auth.NewStore(testPool)
	ctx := t.Context()
	user := seedUser(t, store, "rotate@example.com")

	const oldHash = "rotation-old-hash"
	const newHash = "rotation-new-hash"
	if err := store.CreateRefreshToken(ctx, user.ID, oldHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateRefreshToken(old): %v", err)
	}

	// Rotate: consume old, issue new.
	if _, err := store.ConsumeRefreshToken(ctx, oldHash); err != nil {
		t.Fatalf("ConsumeRefreshToken(old) during rotation: %v", err)
	}
	if err := store.CreateRefreshToken(ctx, user.ID, newHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateRefreshToken(new): %v", err)
	}

	// The old hash is gone for good.
	if _, err := store.ConsumeRefreshToken(ctx, oldHash); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("post-rotation old-hash consume err = %v, want auth.ErrNotFound", err)
	}
	// The new hash consumes once, to the same user.
	row, err := store.ConsumeRefreshToken(ctx, newHash)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken(new): %v", err)
	}
	if row.UserID != user.ID {
		t.Errorf("rotated token user_id = %v, want %v", row.UserID, user.ID)
	}
	// And the new hash is now single-use too.
	if _, err := store.ConsumeRefreshToken(ctx, newHash); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("post-rotation new-hash second consume err = %v, want auth.ErrNotFound", err)
	}
}
