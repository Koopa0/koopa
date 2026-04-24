package hypothesis

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestUpdateState_RejectsEvidenceStates is the H3a (db-reviewer) guard.
// UpdateState used to accept verified/invalidated as values, send them
// to the DB, and let chk_hypothesis_resolved_at surface as an opaque
// 23514. Now the method short-circuits with ErrInvalidTransition before
// any DB round-trip, so callers are forced onto UpdateResolution (which
// writes evidence + resolved_at atomically).
//
// A nil db.DBTX is safe here because the guard returns before the
// generated query tries to touch the connection.
func TestUpdateState_RejectsEvidenceStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
	}{
		{name: "verified", state: StateVerified},
		{name: "invalidated", state: StateInvalidated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewStore(nil)
			rec, err := s.UpdateState(t.Context(), uuid.New(), tt.state)

			if rec != nil {
				t.Errorf("UpdateState(%s) rec = %+v, want nil", tt.state, rec)
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("UpdateState(%s) err = %v, want ErrInvalidTransition", tt.state, err)
			}
		})
	}
}
