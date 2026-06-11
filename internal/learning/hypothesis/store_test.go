// Copyright 2026 Koopa. All rights reserved.

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

// TestUpdateState_RejectsDraftTarget guards the v3.1 draft machine:
// nothing transitions TO draft. draft is exclusively an initial state set
// at creation; if UpdateState ever accepted it, an endorsed (or archived)
// hypothesis could be silently demoted back to the pre-endorsement state.
// A nil db.DBTX is safe because the guard returns before any DB call.
func TestUpdateState_RejectsDraftTarget(t *testing.T) {
	t.Parallel()

	s := NewStore(nil)
	rec, err := s.UpdateState(t.Context(), uuid.New(), StateDraft)

	if rec != nil {
		t.Errorf("UpdateState(draft) rec = %+v, want nil", rec)
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("UpdateState(draft) err = %v, want ErrInvalidTransition", err)
	}
}

// TestCreate_InitialStateValidation pins the only two legal birth states.
// Resolved states (verified/invalidated/archived) exist solely as
// transition outcomes — a Create that accepted them would mint permanent
// records that skipped the whole lifecycle (and, for verified/invalidated,
// would only fail later as an opaque 23514 from chk_resolved_at). A nil
// db.DBTX is safe for the rejecting rows because the guard precedes the
// query; the accepting states are covered by integration tests.
func TestCreate_InitialStateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
	}{
		{name: "verified", state: StateVerified},
		{name: "invalidated", state: StateInvalidated},
		{name: "archived", state: StateArchived},
		{name: "garbage", state: State("garbage")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewStore(nil)
			rec, err := s.Create(t.Context(), &CreateParams{
				CreatedBy:             "human",
				Claim:                 "c",
				InvalidationCondition: "i",
				State:                 tt.state,
			})

			if rec != nil {
				t.Errorf("Create(state=%s) rec = %+v, want nil", tt.state, rec)
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("Create(state=%s) err = %v, want ErrInvalidTransition", tt.state, err)
			}
		})
	}
}
