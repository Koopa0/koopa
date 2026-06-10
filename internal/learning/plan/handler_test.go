// Copyright 2026 Koopa. All rights reserved.

package plan

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Handler.Create — input validation (real Handler, nil store)
// The decision-stamp create requires a non-empty title and domain;
// validation rejects before the per-request tx / store is touched, so a nil
// store is safe for these cases.
// ---------------------------------------------------------------------------

func TestHandler_Create_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "missing title returns 400", body: `{"domain":"leetcode"}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "missing domain returns 400", body: `{"title":"N2 Plan"}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "empty title returns 400", body: `{"title":"","domain":"leetcode"}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "control char in title returns 400", body: "{\"title\":\"bad\\u0001title\",\"domain\":\"leetcode\"}", wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "control char in description returns 400", body: "{\"title\":\"N2\",\"domain\":\"leetcode\",\"description\":\"bad\\u0001desc\"}", wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "control char in domain returns 400", body: "{\"title\":\"N2\",\"domain\":\"bad\\u0001domain\"}", wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "malformed JSON returns 400", body: `{bad}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "empty body returns 400", body: ``, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/api/admin/learning/plans", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Create(%q) status = %d, want %d (body: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("Create(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}

// TestActorFromContext_FallsBackToHuman verifies the created_by stamp
// defaults to "human" when no actor is present in context (the admin-write
// convention) — exercised here without a request through the middleware.
func TestActorFromContext_FallsBackToHuman(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api/admin/learning/plans", http.NoBody)
	if got := actorFromContext(req); got != "human" {
		t.Errorf("actorFromContext(bare request) = %q, want %q", got, "human")
	}
}

// ---------------------------------------------------------------------------
// Handler.AddEntries — bounds validation (real Handler, nil store)
// An empty or oversized entries list rejects with 400 before mustAdminTx /
// the store is touched, so a nil store is safe for these cases.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Handler.UpdateStatus — lifecycle enum validation (real Handler, nil store)
// The status enum gate rejects before mustAdminTx / the store is touched, so
// a nil store is safe for these cases.
// ---------------------------------------------------------------------------

func TestHandler_UpdateStatus_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))
	planID := uuid.New().String()

	tests := []struct {
		name       string
		id         string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "invalid plan id returns 400", id: "not-a-uuid", body: `{"status":"active"}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "malformed JSON returns 400", id: planID, body: `{bad}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "missing status returns 400", id: planID, body: `{}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "unknown enum value returns 400", id: planID, body: `{"status":"archived"}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPut, "/api/admin/learning/plans/"+tt.id+"/status", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()
			h.UpdateStatus(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("UpdateStatus(%q) status = %d, want %d (body: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("UpdateStatus(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler.Reorder — list-shape validation (real Handler, nil store)
// Empty lists, missing/duplicate ids, duplicate or negative positions all
// reject before mustAdminTx / the store is touched, so a nil store is safe.
// ---------------------------------------------------------------------------

func TestHandler_Reorder_Validation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))
	planID := uuid.New().String()
	entryA := uuid.New().String()
	entryB := uuid.New().String()

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "empty entries returns 400", body: `{"entries":[]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "malformed JSON returns 400", body: `{bad}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "missing plan_entry_id returns 400", body: `{"entries":[{"position":1}]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "negative position returns 400", body: `{"entries":[{"plan_entry_id":"` + entryA + `","position":-1}]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "duplicate plan_entry_id returns 400", body: `{"entries":[{"plan_entry_id":"` + entryA + `","position":1},{"plan_entry_id":"` + entryA + `","position":2}]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "duplicate position returns 400", body: `{"entries":[{"plan_entry_id":"` + entryA + `","position":1},{"plan_entry_id":"` + entryB + `","position":1}]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPut, "/api/admin/learning/plans/"+planID+"/reorder", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", planID)
			w := httptest.NewRecorder()
			h.Reorder(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("Reorder(%q) status = %d, want %d (body: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("Reorder(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestHandler_AddEntries_BoundsValidation(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, slog.New(slog.DiscardHandler))
	planID := uuid.New().String()

	oversized := AddEntriesRequest{Entries: make([]NewEntry, maxEntriesPerRequest+1)}
	for i := range oversized.Entries {
		oversized.Entries[i].LearningTargetID = uuid.New()
	}
	oversizedBody, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("marshaling oversized request: %v", err)
	}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "empty entries returns 400", body: `{"entries":[]}`, wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
		{name: "oversized entries returns 400", body: string(oversizedBody), wantStatus: http.StatusBadRequest, wantCode: "BAD_REQUEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/api/admin/learning/plans/"+planID+"/entries", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", planID)
			w := httptest.NewRecorder()
			h.AddEntries(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("AddEntries(%q) status = %d, want %d (body: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			var eb api.ErrorBody
			if err := json.NewDecoder(w.Body).Decode(&eb); err != nil {
				t.Fatalf("decoding error body: %v", err)
			}
			if eb.Error.Code != tt.wantCode {
				t.Errorf("AddEntries(%q) error.code = %q, want %q", tt.name, eb.Error.Code, tt.wantCode)
			}
		})
	}
}
