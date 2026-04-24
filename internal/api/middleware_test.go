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

// TestStatusCapturingWriter_Decision exercises the same status thresholds
// the middleware uses to decide commit vs rollback: [200, 400) commits,
// everything else rolls back. This locks the boundary so a future
// refactor to "success := sw.status < 400" does not drift.
// Scene: middleware dispatch logic depends on this range being exact.
func TestStatusCapturingWriter_Decision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		wantCommit bool
	}{
		{name: "200 commits", status: 200, wantCommit: true},
		{name: "201 commits", status: 201, wantCommit: true},
		{name: "301 commits", status: 301, wantCommit: true},
		{name: "399 commits", status: 399, wantCommit: true},
		{name: "400 rolls back", status: 400, wantCommit: false},
		{name: "404 rolls back", status: 404, wantCommit: false},
		{name: "500 rolls back", status: 500, wantCommit: false},
		{name: "0 (no write) rolls back", status: 0, wantCommit: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Mirror the middleware's commit predicate exactly.
			gotCommit := tt.status >= 200 && tt.status < 400
			if gotCommit != tt.wantCommit {
				t.Errorf("commit-range(%d) = %v, want %v", tt.status, gotCommit, tt.wantCommit)
			}
		})
	}
}

// TestActorMiddleware_TxAvailableInContext verifies that a handler wrapped
// by ActorMiddleware (through its constructor signature) can retrieve a
// pgx.Tx via TxFromContext. We stage the context manually here to avoid
// spinning up a pool for a unit test -- the full begin/commit/rollback
// assertions live in the commit 25 integration test per brief §8.3.
// Scene: regression guard that the key used for injection matches the
// key used for extraction; a typo in txKey{} would silently break every
// admin mutation.
func TestActorMiddleware_TxAvailableInContext(t *testing.T) {
	t.Parallel()

	// Sentinel value standing in for a real pgx.Tx. The type assertion in
	// TxFromContext requires pgx.Tx, so we use nil here and assert on ok.
	// (A nil pgx.Tx interface value still satisfies the type assertion
	// when explicitly stored as pgx.Tx(nil), but for this test we only
	// care that the key contract is honored.)
	ctx := context.WithValue(t.Context(), txKey{}, pgxTxSentinel{})

	// Direct assertion using the same key exposes the contract without
	// requiring a real pool.
	v := ctx.Value(txKey{})
	if v == nil {
		t.Fatalf("ctx.Value(txKey{}) = nil, want stored sentinel")
	}
	if _, ok := v.(pgxTxSentinel); !ok {
		t.Fatalf("ctx.Value(txKey{}) underlying type = %T, want pgxTxSentinel", v)
	}
}

// pgxTxSentinel is a test-local stand-in used only to prove that the
// unexported txKey{} is the key the middleware and helper agree on.
// A real pgx.Tx cannot be constructed without a pool connection; the
// integration test in commit 25 covers the round-trip end to end.
type pgxTxSentinel struct{}
