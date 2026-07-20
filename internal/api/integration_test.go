// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for ActorMiddleware's end-to-end contract: a real
// admin request with the middleware wired opens a pgxpool transaction,
// binds koopa.actor via SELECT set_config, carries the tx into the
// handler context, commits on 2xx, and the audit trigger on the mutated
// table records the expected actor.
//
// Two complementary tests live here:
//
//  1. TestActorMiddleware_PropagatesActorThroughProductionTransition — the happy path that
//     asserts the handler routes its store through WithTx(tx) and the
//     audit row lands with the configured actor.
//
//  2. TestActorMiddleware_SilentDegradation_WhenWithTxForgotten — the
//     failure mode that commit 21's middleware intentionally tolerates:
//     if a handler ignores api.TxFromContext and uses the bare pool, the
//     transition still works but the audit trigger sees an empty koopa.actor
//     and falls back to 'human'. Per brief §8.5 this test documents the
//     risk so future reviewers audit every admin mutation wired by the
//     middleware.
//
// The concrete production vehicle is the content SubmitForReview route: its
// audit trigger writes activity_events with actor=current_actor() on the
// draft → review transition, exactly the propagation contract.
//
// Known coverage gap (review-code M8 backlog):
// This file asserts the WithTx contract on ONE route (content SubmitForReview).
// The other audited admin mutations (project / goal / topic / feed /
// feed/entry / hypothesis + sub-routes) are covered by per-feature
// integration tests that exercise the WithTx path when wired, but there is
// no single table-driven proof-of-universal-coverage here.
// If a future dev adds a new admin route and forgets store.WithTx(tx),
// no test in this file will catch it. The practical guard is the code
// review pattern documented in cmd/app/routes.go + the existing silent-
// degradation test below (which proves the failure mode is REAL, making
// it reviewable).
//
// Extending this file to a table-driven sweep would require wiring every
// handler's full dependency graph (stores, seed data per route, full
// adminMid chain) — essentially duplicating cmd/app/main.go in test
// scaffolding. Deferred as backlog rather than risk a brittle
// duplicate-of-main bit-rot trap.
//
// Run with:
//
//	go test -tags=integration ./internal/api/...
package api_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// The audit trigger on contents writes activity_events.actor which has
	// an FK onto agents. Without reconciling the builtin registry, every
	// content insert fails with 23503 before the middleware contract can be
	// exercised. Matches cmd/app/main.go startup.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// truncateContents wipes every table the content create path can write to so a
// previous test's row cannot satisfy the "most recent content" query used by
// the assertions.
func truncateContents(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE contents, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// actorForContent reads the activity_events.actor column for the given content
// id. Fails the test if no row is found — absence means the audit trigger
// silently didn't fire, which is itself a regression.
func actorForContent(t *testing.T, contentID uuid.UUID) string {
	t.Helper()
	var actor string
	err := testPool.QueryRow(t.Context(),
		`SELECT actor FROM activity_events
		 WHERE entity_type = 'content' AND entity_id = $1
		 ORDER BY occurred_at DESC LIMIT 1`,
		contentID,
	).Scan(&actor)
	if err != nil {
		t.Fatalf("fetching activity_events for content %s: %v", contentID, err)
	}
	return actor
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

// TestActorMiddleware_PropagatesActorThroughProductionTransition wires the
// production SubmitForReview handler (which routes through api.TxFromContext
// via mustAdminTx) behind ActorMiddleware and asserts the audit row lands with
// the configured actor. This is the happy-path regression guard for commit 21 —
// any future change that breaks the tx-in-context contract fails here.
func TestActorMiddleware_PropagatesActorThroughProductionTransition(t *testing.T) {
	truncateContents(t)

	logger := slog.Default()
	contentStore := content.NewStore(testPool)
	path := "Writing/tests/actor-middleware.md"
	sha := "0123456789abcdef0123456789abcdef01234567"
	created, err := contentStore.CreateContent(t.Context(), &content.CreateParams{
		Slug: "actor-transition-" + randomHex(t, 8), Title: "Actor transition",
		Body: "integration-test body", Type: content.TypeArticle, Status: content.StatusDraft,
		SourceVaultPath: &path, SourceGitBlobSHA: &sha,
	})
	if err != nil {
		t.Fatalf("seed source-bound draft: %v", err)
	}
	h := content.NewHandler(contentStore, "https://example.test", logger)

	mid := api.ActorMiddleware(testPool, "codex", logger)
	wrapped := mid(http.HandlerFunc(h.SubmitForReview))

	req := httptest.NewRequest(http.MethodPost,
		"/api/admin/knowledge/content/"+created.ID.String()+"/submit-for-review", http.NoBody)
	req.SetPathValue("id", created.ID.String())
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, string(bodyBytes))
	}

	if got := actorForContent(t, created.ID); got != "codex" {
		t.Errorf("activity_events.actor = %q, want %q (tx-in-context did not propagate)", got, "codex")
	}
}

// TestActorMiddleware_SilentDegradation_WhenWithTxForgotten documents the
// failure mode per brief §8.5. It wires a deliberately-wrong handler that
// ignores api.TxFromContext and uses the bare pool-backed store, with the
// middleware intending a non-human actor ('codex'). The transition still
// succeeds because the audit trigger falls back to 'human' when koopa.actor is
// unset — but the recorded actor is 'human', NOT the intended 'codex', so the
// write is silently misattributed. Future reviewers: if you extend adminMid to
// a new handler, route through WithTx(tx) or the trigger will misattribute.
func TestActorMiddleware_SilentDegradation_WhenWithTxForgotten(t *testing.T) {
	truncateContents(t)

	logger := slog.Default()
	contentStore := content.NewStore(testPool)
	path := "Writing/tests/forgotten-actor.md"
	sha := "0123456789abcdef0123456789abcdef01234567"
	created, err := contentStore.CreateContent(t.Context(), &content.CreateParams{
		Slug: "forgotten-actor-" + randomHex(t, 8), Title: "Forgotten actor",
		Body: "integration-test body", Type: content.TypeArticle, Status: content.StatusDraft,
		SourceVaultPath: &path, SourceGitBlobSHA: &sha,
	})
	if err != nil {
		t.Fatalf("seed source-bound draft: %v", err)
	}

	// Forgetful handler: performs the same store transition as the production
	// SubmitForReview handler, but ignores api.TxFromContext and uses the bare
	// pool-backed store.
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The important omission: NO api.TxFromContext call. The store sees
		// the raw pool and the audit trigger never observes the middleware's
		// koopa.actor binding.
		c, err := contentStore.SubmitContentForReview(r.Context(), created.ID)
		if err != nil {
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "transition failed: "+err.Error())
			return
		}
		api.Encode(w, http.StatusOK, api.Response{Data: c})
	})

	mid := api.ActorMiddleware(testPool, "codex", logger)
	wrapped := mid(forgetful)

	req := httptest.NewRequest(http.MethodPost,
		"/api/admin/knowledge/content/"+created.ID.String()+"/submit-for-review", http.NoBody)
	req.SetPathValue("id", created.ID.String())
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (forgetful handler still writes; body=%s)", resp.StatusCode, string(bodyBytes))
	}

	if got := actorForContent(t, created.ID); got != "human" {
		t.Errorf("activity_events.actor = %q, want %q (silent degradation: tx binding never reached the store, so the trigger fell back to the owner instead of the intended 'codex')", got, "human")
	}
}
