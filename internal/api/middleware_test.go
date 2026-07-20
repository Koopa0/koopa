// Copyright 2026 Koopa. All rights reserved.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTxFromContext_NotPresent verifies that a bare context -- e.g. a
// non-admin request that never passed through ActorMiddleware -- returns
// (nil, false) so handlers can detect wiring gaps without panicking.
// Scene: a handler wired under the public router calls TxFromContext
// defensively; it must not panic when the middleware is absent.
func TestTxFromContext_NotPresent(t *testing.T) {
	t.Parallel()

	tx, ok := TxFromContext(t.Context())
	if ok {
		t.Errorf("TxFromContext(bare ctx) ok = true, want false")
	}
	if tx != nil {
		t.Errorf("TxFromContext(bare ctx) tx = %v, want nil", tx)
	}
}

// TestTxFromContext_WrongType verifies that a value stored under a
// different context key type does not accidentally satisfy the
// TxFromContext type assertion. This guards against a future refactor
// that reuses the key under a different value type.
// Scene: regression guard on the unexported txKey{} contract.
func TestTxFromContext_WrongType(t *testing.T) {
	t.Parallel()

	// Store a non-pgx.Tx value under an UNRELATED key. TxFromContext must
	// still return (nil, false) because it looks up txKey{}, not any key.
	type otherKey struct{}
	ctx := context.WithValue(t.Context(), otherKey{}, "not a tx")
	tx, ok := TxFromContext(ctx)
	if ok {
		t.Errorf("TxFromContext(other-key ctx) ok = true, want false")
	}
	if tx != nil {
		t.Errorf("TxFromContext(other-key ctx) tx = %v, want nil", tx)
	}
}

// TestStatusCapturingWriter covers the pure status-capture behavior
// independent of any pgx.Tx wiring. The tx-lifecycle assertions (commit
// on 2xx, rollback on 4xx/5xx, set_config executed) run in the
// commit 25 integration test against a real pool -- see brief §8.3.
// Scene: middleware decides commit vs rollback purely from the captured
// status; this test locks the capture semantics.
func TestStatusCapturingWriter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		act        func(sw *statusCapturingWriter)
		wantStatus int
	}{
		{
			name:       "no write defaults to zero",
			act:        func(sw *statusCapturingWriter) {},
			wantStatus: 0,
		},
		{
			name: "explicit 200",
			act: func(sw *statusCapturingWriter) {
				sw.WriteHeader(http.StatusOK)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "explicit 400",
			act: func(sw *statusCapturingWriter) {
				sw.WriteHeader(http.StatusBadRequest)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "explicit 500",
			act: func(sw *statusCapturingWriter) {
				sw.WriteHeader(http.StatusInternalServerError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "Write without WriteHeader records 200",
			act: func(sw *statusCapturingWriter) {
				_, _ = sw.Write([]byte("body"))
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "double WriteHeader keeps first",
			act: func(sw *statusCapturingWriter) {
				sw.WriteHeader(http.StatusCreated)
				sw.WriteHeader(http.StatusInternalServerError)
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "WriteHeader then Write keeps first status",
			act: func(sw *statusCapturingWriter) {
				sw.WriteHeader(http.StatusAccepted)
				_, _ = sw.Write([]byte("body"))
			},
			wantStatus: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			sw := &statusCapturingWriter{ResponseWriter: rec}
			tt.act(sw)
			if sw.status != tt.wantStatus {
				t.Errorf("statusCapturingWriter.status = %d, want %d", sw.status, tt.wantStatus)
			}
		})
	}
}

// TestStatusCapturingWriter_UnwrapReturnsInner verifies that Unwrap
// exposes the wrapped writer so http.ResponseController can discover
// http.Flusher and friends on the inner writer. Without this, SSE-style
// endpoints wrapped by ActorMiddleware would lose flush capability.
// Scene: a future admin endpoint streams progress via Flusher; the
// capturing writer must not hide that capability.
func TestStatusCapturingWriter_UnwrapReturnsInner(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := &statusCapturingWriter{ResponseWriter: rec}

	inner := sw.Unwrap()
	if inner != rec {
		t.Errorf("statusCapturingWriter.Unwrap() = %v, want the wrapped *httptest.ResponseRecorder", inner)
	}
}

// The status thresholds the middleware uses to decide commit vs rollback
// ([200, 400) commits, everything else rolls back) are exercised end to end —
// against a real pool, asserting the audit row actually commits/rolls back — by
// TestActorMiddleware_PropagatesActorThroughProductionTransition in api
// integration_test.go. A unit
// test that re-implements the `status >= 200 && status < 400` predicate and
// compares it to itself would be a tautology (testing.md Low-Value #1/#2), so it
// is intentionally absent here.
//
// Likewise, the tx-in-context round-trip (ActorMiddleware injects a pgx.Tx that
// the handler retrieves via TxFromContext) is covered by that same integration
// test, which drives content.Handler.SubmitForReview — a real handler that
// reads api.TxFromContext — through ActorMiddleware against a real pool. The
// unexported txKey{} contract is therefore proven by exercising the real code
// path rather than by a context.WithValue/Value round-trip that never touches
// the middleware.
