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
