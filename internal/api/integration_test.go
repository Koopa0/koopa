//go:build integration

// Integration coverage for ActorMiddleware's end-to-end contract: a real
// admin request with the middleware wired opens a pgxpool transaction,
// binds koopa.actor via SELECT set_config, carries the tx into the
// handler context, commits on 2xx, and the audit trigger on the mutated
// table records the expected actor.
//
// Two complementary tests live here:
//
//  1. TestActorMiddleware_PropagatesHumanActor — the happy path that
//     asserts the handler routes its store through WithTx(tx) and the
//     audit row lands with actor='human'.
//
//  2. TestActorMiddleware_SilentDegradation_WhenWithTxForgotten — the
//     failure mode that commit 21's middleware intentionally tolerates:
//     if a handler ignores api.TxFromContext and uses the bare pool, the
//     insert still works but the audit trigger sees an empty koopa.actor
//     and falls back to 'system'. Per brief §8.5 this test documents the
//     risk so future reviewers audit every admin mutation wired by the
//     middleware.
//
// Known coverage gap (review-code M8 backlog):
// This file asserts the WithTx contract on ONE route (bookmark Create).
// The other ~29 audited admin mutations (content / project / goal / topic
// / tag / feed / feed/entry / hypothesis + sub-routes) are covered by
// per-feature integration tests that exercise the WithTx path when wired,
// but there is no single table-driven proof-of-universal-coverage here.
// If a future dev adds a new admin route and forgets store.WithTx(tx),
// no test in this file will catch it. The practical guard is the code
// review pattern documented in cmd/app/routes.go + the existing silent-
// degradation test below (which proves the failure mode is REAL, making
// it reviewable).
//
// Extending this file to a table-driven sweep would require wiring every
// handler's full dependency graph (11 stores, seed data per route,
// full adminMid chain) — essentially duplicating cmd/app/main.go in
// test scaffolding. Deferred as backlog rather than risk a brittle
// duplicate-of-main bit-rot trap.
//
// Run with:
//
//	go test -tags=integration ./internal/api/...
package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

	// The audit trigger on bookmarks writes activity_events.actor which
	// has an FK onto agents. Without reconciling the builtin registry,
	// every bookmark insert fails with 23503 before the middleware
	// contract can be exercised. Matches cmd/app/main.go startup.
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

// truncateBookmarks wipes every table the bookmark create path can write
// to so a previous test's row cannot satisfy the "most recent bookmark"
// query used by the assertions.
func truncateBookmarks(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE bookmark_topics, bookmark_tags, bookmarks, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// actorForBookmark reads the activity_events.actor column for the most
// recent bookmark-type row. Fails the test if no row is found — absence
// means the audit trigger silently didn't fire, which is itself a
// regression.
func actorForBookmark(t *testing.T, bookmarkID uuid.UUID) string {
	t.Helper()
	var actor string
	err := testPool.QueryRow(t.Context(),
		`SELECT actor FROM activity_events
		 WHERE entity_type = 'bookmark' AND entity_id = $1
		 ORDER BY occurred_at DESC LIMIT 1`,
		bookmarkID,
	).Scan(&actor)
	if err != nil {
		t.Fatalf("fetching activity_events for bookmark %s: %v", bookmarkID, err)
	}
	return actor
}

// postBookmark builds a POST /api/admin/bookmarks request body with a
// unique URL so successive calls don't collide on url_hash.
func postBookmark(t *testing.T, title string) *http.Request {
	t.Helper()
	body := bookmark.CreateRequest{
		URL:            "https://example.com/" + randomHex(t, 16),
		Title:          title,
		Excerpt:        "integration-test excerpt",
		Note:           "integration-test note",
		CaptureChannel: bookmark.ChannelManual,
		IsPublic:       false,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal bookmark body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/bookmarks", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// randomHex returns a hex-encoded string backed by crypto/rand.
func randomHex(t *testing.T, size int) string {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand read: %v", err)
	}
	return hex.EncodeToString(b)
}

// sha256Hex mirrors internal/bookmark/handler.go's hashURL. Reproduced
// here because the forgetful handler cannot import an unexported helper.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return hex.EncodeToString(sum[:])
}

// slugFromTitle mirrors internal/bookmark/handler.go's slugify with a
// tiny tweak: it appends random entropy so successive silent-degradation
// inserts don't collide on uniq_bookmarks_slug.
func slugFromTitle(t *testing.T, title string) string {
	t.Helper()
	lower := strings.ToLower(strings.TrimSpace(title))
	var b strings.Builder
	b.Grow(len(lower))
	lastDash := false
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == ' ' || r == '-' || r == '_':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if s == "" {
		s = "bookmark"
	}
	return s + "-" + randomHex(t, 4)
}

// decodeBookmarkID extracts the created bookmark's id from an
// api.Response envelope.
func decodeBookmarkID(t *testing.T, body []byte) uuid.UUID {
	t.Helper()
	var env struct {
		Data struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, string(body))
	}
	if env.Data.ID == uuid.Nil {
		t.Fatalf("response missing bookmark id: %s", string(body))
	}
	return env.Data.ID
}

// TestActorMiddleware_PropagatesHumanActor wires the production handler
// (bookmark.Handler.Create, which DOES consult api.TxFromContext) behind
// ActorMiddleware and asserts the audit row lands with actor='human'.
// This is the happy-path regression guard for commit 21 — any future
// change that breaks the tx-in-context contract fails here.
func TestActorMiddleware_PropagatesHumanActor(t *testing.T) {
	truncateBookmarks(t)

	logger := slog.Default()
	bookmarkStore := bookmark.NewStore(testPool)
	h := bookmark.NewHandler(bookmarkStore, logger)

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(http.HandlerFunc(h.Create))

	req := postBookmark(t, "Propagates Human Actor")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, string(bodyBytes))
	}

	id := decodeBookmarkID(t, bodyBytes)
	if got := actorForBookmark(t, id); got != "human" {
		t.Errorf("activity_events.actor = %q, want %q (tx-in-context did not propagate)", got, "human")
	}
}

// TestActorMiddleware_SilentDegradation_WhenWithTxForgotten documents
// the failure mode per brief §8.5. It wires a deliberately-wrong handler
// that ignores api.TxFromContext and uses the bare pool-backed store.
// The insert still succeeds (201) because the audit trigger falls back
// to 'system' when koopa.actor is unset — but the recorded actor is
// NOT 'human' anymore. Future reviewers: if you extend adminMid to any
// new handler, check you routed through WithTx(tx) or the trigger will
// silently misattribute the write.
func TestActorMiddleware_SilentDegradation_WhenWithTxForgotten(t *testing.T) {
	truncateBookmarks(t)

	logger := slog.Default()
	bookmarkStore := bookmark.NewStore(testPool)

	// Forgetful handler: writes with the bare pool-backed store and
	// never consults api.TxFromContext. Mirrors the public contract of
	// bookmark.Handler.Create so the middleware path is identical —
	// only the WithTx(tx) call is missing.
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := api.Decode[bookmark.CreateRequest](w, r)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid body")
			return
		}

		params := bookmark.CreateParams{
			URL:            req.URL,
			URLHash:        sha256Hex(req.URL),
			Slug:           slugFromTitle(t, req.Title),
			Title:          req.Title,
			Excerpt:        req.Excerpt,
			Note:           req.Note,
			CaptureChannel: bookmark.ChannelManual,
			CuratedBy:      "human",
			IsPublic:       false,
		}

		// The important omission: NO api.TxFromContext call. The store
		// sees the raw pool and the audit trigger never observes the
		// middleware's koopa.actor binding.
		b, err := bookmarkStore.Create(r.Context(), &params)
		if err != nil {
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "create failed: "+err.Error())
			return
		}
		api.Encode(w, http.StatusCreated, api.Response{Data: b})
	})

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(forgetful)

	req := postBookmark(t, "Silent Degradation")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (forgetful handler still writes; body=%s)", resp.StatusCode, string(bodyBytes))
	}

	id := decodeBookmarkID(t, bodyBytes)
	if got := actorForBookmark(t, id); got != "system" {
		t.Errorf("activity_events.actor = %q, want %q (silent-degradation failure mode: tx binding didn't reach the store, trigger fell back)", got, "system")
	}
}
