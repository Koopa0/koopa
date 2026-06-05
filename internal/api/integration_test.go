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
// Known coverage gap (review-code M8 backlog):
// This file asserts the WithTx contract on ONE route (note Create).
// The other audited admin mutations (content / project / goal / topic
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
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// The audit trigger on notes writes activity_events.actor which has an
	// FK onto agents. Without reconciling the builtin registry, every note
	// insert fails with 23503 before the middleware contract can be
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

// truncateNotes wipes every table the note create path can write to so a
// previous test's row cannot satisfy the "most recent note" query used by
// the assertions.
func truncateNotes(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE notes, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// actorForNote reads the activity_events.actor column for the given note
// id. Fails the test if no row is found — absence means the audit trigger
// silently didn't fire, which is itself a regression.
func actorForNote(t *testing.T, noteID uuid.UUID) string {
	t.Helper()
	var actor string
	err := testPool.QueryRow(t.Context(),
		`SELECT actor FROM activity_events
		 WHERE entity_type = 'note' AND entity_id = $1
		 ORDER BY occurred_at DESC LIMIT 1`,
		noteID,
	).Scan(&actor)
	if err != nil {
		t.Fatalf("fetching activity_events for note %s: %v", noteID, err)
	}
	return actor
}

// noteBody is the POST /api/admin/knowledge/notes request shape. created_by
// is not caller-supplied — the middleware actor fills it — so it is absent
// here, mirroring the production createRequest.
type noteBody struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
	Body  string `json:"body"`
	Kind  string `json:"kind"`
}

// postNote builds a POST /api/admin/knowledge/notes request with a unique
// slug so successive calls don't collide on the notes slug UNIQUE index.
func postNote(t *testing.T, title string) *http.Request {
	t.Helper()
	body := noteBody{
		Slug:  "note-" + randomHex(t, 8),
		Title: title,
		Body:  "integration-test body",
		Kind:  string(note.KindMusing),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal note body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/knowledge/notes", bytes.NewReader(buf))
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

// decodeNoteID extracts the created note's id from an api.Response
// envelope.
func decodeNoteID(t *testing.T, body []byte) uuid.UUID {
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
		t.Fatalf("response missing note id: %s", string(body))
	}
	return env.Data.ID
}

// TestActorMiddleware_PropagatesHumanActor wires the production handler
// (note.Handler.Create, which requires api.TxFromContext via mustAdminTx)
// behind ActorMiddleware and asserts the audit row lands with
// actor='human'. This is the happy-path regression guard for commit 21 —
// any future change that breaks the tx-in-context contract fails here.
func TestActorMiddleware_PropagatesHumanActor(t *testing.T) {
	truncateNotes(t)

	logger := slog.Default()
	noteStore := note.NewStore(testPool)
	h := note.NewHandler(noteStore, logger)

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(http.HandlerFunc(h.Create))

	req := postNote(t, "Propagates Human Actor")
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

	id := decodeNoteID(t, bodyBytes)
	if got := actorForNote(t, id); got != "human" {
		t.Errorf("activity_events.actor = %q, want %q (tx-in-context did not propagate)", got, "human")
	}
}

// TestActorMiddleware_SilentDegradation_WhenWithTxForgotten documents the
// failure mode per brief §8.5. It wires a deliberately-wrong handler that
// ignores api.TxFromContext and uses the bare pool-backed store. The
// insert still succeeds (201) because the audit trigger falls back to
// 'system' when koopa.actor is unset — but the recorded actor is NOT
// 'human' anymore. Future reviewers: if you extend adminMid to any new
// handler, check you routed through WithTx(tx) or the trigger will
// silently misattribute the write.
func TestActorMiddleware_SilentDegradation_WhenWithTxForgotten(t *testing.T) {
	truncateNotes(t)

	logger := slog.Default()
	noteStore := note.NewStore(testPool)

	// Forgetful handler: writes with the bare pool-backed store and never
	// consults api.TxFromContext. Mirrors the public contract of
	// note.Handler.Create so the middleware path is identical — only the
	// WithTx(tx) call is missing.
	forgetful := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := api.Decode[noteBody](w, r)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid body")
			return
		}

		params := &note.CreateParams{
			Slug:      req.Slug,
			Title:     req.Title,
			Body:      req.Body,
			Kind:      note.Kind(req.Kind),
			CreatedBy: "human",
		}

		// The important omission: NO api.TxFromContext call. The store sees
		// the raw pool and the audit trigger never observes the middleware's
		// koopa.actor binding.
		n, err := noteStore.Create(r.Context(), params)
		if err != nil {
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "create failed: "+err.Error())
			return
		}
		api.Encode(w, http.StatusCreated, api.Response{Data: n})
	})

	mid := api.ActorMiddleware(testPool, "human", logger)
	wrapped := mid(forgetful)

	req := postNote(t, "Silent Degradation")
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

	id := decodeNoteID(t, bodyBytes)
	if got := actorForNote(t, id); got != "system" {
		t.Errorf("activity_events.actor = %q, want %q (silent-degradation failure mode: tx binding didn't reach the store, trigger fell back)", got, "system")
	}
}
