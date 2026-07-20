// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// These test-local contracts let the regression suite remain buildable on the
// pre-withdrawal base. The RED is therefore the missing behavior, not an
// unrelated compiler failure. Production remains free of test-only interfaces.
type withdrawalStore interface {
	Withdraw(context.Context, uuid.UUID, string) (*Content, error)
	Restore(context.Context, uuid.UUID) (*Content, error)
}

type withdrawalHandler interface {
	Withdraw(http.ResponseWriter, *http.Request)
	Restore(http.ResponseWriter, *http.Request)
}

func requireWithdrawalStore(t *testing.T, store *Store) withdrawalStore {
	t.Helper()
	lifecycle, ok := any(store).(withdrawalStore)
	if !ok {
		t.Fatal("Store does not implement dedicated Withdraw and Restore transitions")
	}
	return lifecycle
}

func requireWithdrawalHandler(t *testing.T, handler *Handler) withdrawalHandler {
	t.Helper()
	lifecycle, ok := any(handler).(withdrawalHandler)
	if !ok {
		t.Fatal("Handler does not implement dedicated Withdraw and Restore transitions")
	}
	return lifecycle
}

func TestHandler_WithdrawRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	actions := requireWithdrawalHandler(t, newTestHandler())
	validID := uuid.New().String()
	tests := []struct {
		name string
		id   string
		body string
	}{
		{name: "invalid id", id: "not-a-uuid", body: `{"reason":"superseded"}`},
		{name: "malformed json", id: validID, body: `{bad json`},
		{name: "missing reason", id: validID, body: `{}`},
		{name: "empty reason", id: validID, body: `{"reason":""}`},
		{name: "whitespace reason", id: validID, body: `{"reason":"  \t "}`},
		{name: "oversized reason", id: validID, body: `{"reason":"` + strings.Repeat("x", MaxWithdrawalReasonLen+1) + `"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost,
				"/api/admin/knowledge/content/"+tc.id+"/withdraw",
				strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tc.id)
			w := httptest.NewRecorder()

			actions.Withdraw(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("Withdraw(%q, %q) status = %d, want %d (body=%s)",
					tc.id, tc.body, w.Code, http.StatusBadRequest, w.Body.String())
			}
			got := decodeErrorBody(t, w.Body)
			if got.Error.Code != "BAD_REQUEST" {
				t.Errorf("Withdraw(%q, %q) error.code = %q, want %q",
					tc.id, tc.body, got.Error.Code, "BAD_REQUEST")
			}
		})
	}
}

func TestHandler_RestoreRejectsInvalidID(t *testing.T) {
	t.Parallel()

	actions := requireWithdrawalHandler(t, newTestHandler())
	req := httptest.NewRequest(http.MethodPost,
		"/api/admin/knowledge/content/not-a-uuid/restore", http.NoBody)
	req.SetPathValue("id", "not-a-uuid")
	w := httptest.NewRecorder()

	actions.Restore(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Restore(invalid ID) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	got := decodeErrorBody(t, w.Body)
	if got.Error.Code != "BAD_REQUEST" {
		t.Errorf("Restore(invalid ID) error.code = %q, want %q", got.Error.Code, "BAD_REQUEST")
	}
}
