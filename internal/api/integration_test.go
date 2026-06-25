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
// The concrete vehicle is the content Create route (POST /api/admin/knowledge/content):
// its audit trigger writes activity_events with actor=current_actor() on
// INSERT, exactly the propagation the middleware contract guarantees.
//
// Known coverage gap (review-code M8 backlog):
// This file asserts the WithTx contract on ONE route (content Create).
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

// contentBody is the POST /api/admin/knowledge/content request shape. The audit actor
// is supplied by the middleware via set_config, not the request body, so no
// author field appears here — mirroring the production CreateParams.
type contentBody struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
	Body  string `json:"body"`
	Type  string `json:"type"`
}

// postContent builds a POST /api/admin/knowledge/content request with a unique slug so
// successive calls don't collide on the contents slug UNIQUE index.
func postContent(t *testing.T, title string) *http.Request {
	t.Helper()
	body := contentBody{
		Slug:  "content-" + randomHex(t, 8),
		Title: title,
		Body:  "integration-test body",
		Type:  string(content.TypeArticle),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal content body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/knowledge/content", bytes.NewReader(buf))
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

// decodeContentID extracts the created content's id from an api.Response
// envelope.
func decodeContentID(t *testing.T, body []byte) uuid.UUID {
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
		t.Fatalf("response missing content id: %s", string(body))
	}
	return env.Data.ID
}

// TestActorMiddleware_PropagatesHumanActor wires the production handler
// (content.Handler.Create, which routes through api.TxFromContext via
// mustAdminTx) behind ActorMiddleware and asserts the audit row lands with
// actor='human'. This is the happy-path regression guard for commit 21 —
// any future change that breaks the tx-in-context contract fails here.
func TestActorMiddleware_PropagatesHumanActor(t *testing.T) {
	truncateContents(t)

	logger := slog.Default()
	contentStore := content.NewStore(testPool)
	h := content.NewHandler(contentStore, "https://example.test", logger)

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(http.HandlerFunc(h.Create))

	req := postContent(t, "Propagates Human Actor")
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

	id := decodeContentID(t, bodyBytes)
	if got := actorForContent(t, id); got != "human" {
		t.Errorf("activity_events.actor = %q, want %q (tx-in-context did not propagate)", got, "human")
	}
}

// TestActorMiddleware_SilentDegradation_WhenWithTxForgotten documents the
// failure mode per brief §8.5. It wires a deliberately-wrong handler that
// ignores api.TxFromContext and uses the bare pool-backed store, with the
// middleware intending a non-human actor ('codex'). The insert still succeeds
// (201) because the audit trigger falls back to 'human' when koopa.actor is
// unset — but the recorded actor is 'human', NOT the intended 'codex', so the
// write is silently misattributed. Future reviewers: if you extend adminMid to
// a new handler, route through WithTx(tx) or the trigger will misattribute.
func TestActorMiddleware_SilentDegradation_WhenWithTxForgotten(t *testing.T) {
	truncateContents(t)

	logger := slog.Default()
	contentStore := content.NewStore(testPool)

	// Forgetful handler: writes with the bare pool-backed store and never
	// consults api.TxFromContext. Mirrors the public contract of
	// content.Handler.Create so the middleware path is identical — only the
	// WithTx(tx) call is missing.
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := api.Decode[contentBody](w, r)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid body")
			return
		}

		params := &content.CreateParams{
			Slug:   req.Slug,
			Title:  req.Title,
			Body:   req.Body,
			Type:   content.Type(req.Type),
			Status: content.StatusDraft,
		}

		// The important omission: NO api.TxFromContext call. The store sees
		// the raw pool and the audit trigger never observes the middleware's
		// koopa.actor binding.
		c, err := contentStore.CreateContent(r.Context(), params)
		if err != nil {
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "create failed: "+err.Error())
			return
		}
		api.Encode(w, http.StatusCreated, api.Response{Data: c})
	})

	mid := api.ActorMiddleware(testPool, "codex", logger)
	wrapped := mid(forgetful)

	req := postContent(t, "Silent Degradation")
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

	id := decodeContentID(t, bodyBytes)
	if got := actorForContent(t, id); got != "human" {
		t.Errorf("activity_events.actor = %q, want %q (silent degradation: tx binding never reached the store, so the trigger fell back to the owner instead of the intended 'codex')", got, "human")
	}
}
