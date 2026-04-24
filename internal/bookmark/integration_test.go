//go:build integration

// Integration coverage for the bookmark create runtime fix (V3). Before
// commit 21 the admin Create handler stamped curated_by with the
// authenticated user's email or a literal "admin" string, neither of
// which had a matching agents row — the insert failed with 23503 on
// bookmarks_curated_by_fkey. After V3, curatedByFromContext returns the
// literal "human" (the single-admin design) which the builtin registry
// always reconciles. This test POSTs through the real handler and
// confirms the row lands with curated_by='human' and no FK violation.
//
// Run with:
//
//	go test -tags=integration ./internal/bookmark/...
package bookmark_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/bookmark"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// bookmarks.curated_by FKs onto agents. Without the registry seeded
	// the V3 fix cannot be validated because even the happy path would
	// fail FK check.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// randomHex returns a crypto/rand-backed hex string for generating
// unique URLs so successive runs don't collide on uniq_bookmarks_url_hash.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand read: %v", err)
	}
	return hex.EncodeToString(b)
}

// TestBookmarkCreate_NoFKViolation posts through the actor-middleware
// wrapped Create handler and asserts the row lands with curated_by set
// to the project's single-admin identity ("human"). Before V3 this POST
// returned 500 because the handler stamped curated_by with claims.Email
// or literal "admin", neither of which satisfied the FK to agents.
func TestBookmarkCreate_NoFKViolation(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE bookmark_topics, bookmark_tags, bookmarks, activity_events CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	logger := slog.Default()
	store := bookmark.NewStore(testPool)
	h := bookmark.NewHandler(store, logger)

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(http.HandlerFunc(h.Create))

	body, err := json.Marshal(bookmark.CreateRequest{
		URL:            "https://example.com/" + randomHex(t, 16),
		Title:          "V3 FK fix",
		Excerpt:        "integration-test",
		Note:           "regression guard",
		CaptureChannel: bookmark.ChannelManual,
		IsPublic:       false,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/bookmarks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, string(respBody))
	}

	var env struct {
		Data struct {
			ID        uuid.UUID `json:"id"`
			CuratedBy string    `json:"curated_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, string(respBody))
	}

	if env.Data.ID == uuid.Nil {
		t.Fatal("response missing bookmark id")
	}
	if env.Data.CuratedBy != "human" {
		t.Errorf("response.curated_by = %q, want %q", env.Data.CuratedBy, "human")
	}

	// Read back from the DB so the test isn't only trusting the
	// handler's JSON response. The row must exist, which proves the FK
	// didn't reject the insert.
	var dbCuratedBy string
	err = testPool.QueryRow(t.Context(),
		`SELECT curated_by FROM bookmarks WHERE id = $1`, env.Data.ID,
	).Scan(&dbCuratedBy)
	if err != nil {
		t.Fatalf("reading bookmark row: %v", err)
	}
	if dbCuratedBy != "human" {
		t.Errorf("db.curated_by = %q, want %q", dbCuratedBy, "human")
	}
}
