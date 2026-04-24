package hypothesis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for hypotheses.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Create inserts a new hypothesis.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Record, error) {
	r, err := s.q.CreateHypothesis(ctx, db.CreateHypothesisParams{
		CreatedBy:             p.CreatedBy,
		Content:               p.Content,
		Claim:                 p.Claim,
		InvalidationCondition: p.InvalidationCondition,
		Metadata:              p.Metadata,
		ObservedDate:          p.ObservedDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating hypothesis: %w", err)
	}
	return rowToRecord(&r)
}

// RecordByID returns a single hypothesis by ID.
func (s *Store) RecordByID(ctx context.Context, id uuid.UUID) (*Record, error) {
	r, err := s.q.HypothesisByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying hypothesis %s: %w", id, err)
	}
	return rowToRecord(&r)
}

// UpdateState updates a hypothesis's lifecycle state WITHOUT touching
// resolution evidence. Safe only for transitions that do not require
// evidence under chk_hypothesis_resolution (unverified ↔ archived).
// Transitions to verified/invalidated MUST go through UpdateResolution
// so resolved_at and at least one evidence source are written atomically;
// this method returns ErrInvalidTransition for those states rather than
// letting the schema CHECK surface as an opaque 23514.
func (s *Store) UpdateState(ctx context.Context, id uuid.UUID, state State) (*Record, error) {
	if state == StateVerified || state == StateInvalidated {
		return nil, ErrInvalidTransition
	}
	r, err := s.q.UpdateHypothesisState(ctx, db.UpdateHypothesisStateParams{
		ID:    id,
		State: db.HypothesisState(state),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating hypothesis %s state: %w", id, err)
	}
	return rowToRecord(&r)
}

// UpdateResolution atomically sets state + evidence + resolved_at for
// a transition to verified or invalidated. The handler has already
// validated that at least one evidence source is present; this method
// trusts that invariant and maps the DB errors that fall through.
//
// Error mapping (CHECK violations are routed by constraint name so a
// new CHECK added to the table doesn't silently alias into one of the
// existing sentinels):
//   - 23503 (foreign_key_violation) on attempt_id or observation_id →
//     ErrEvidenceNotFound. We do not leak the offending column or
//     constraint name to the caller; the handler returns a generic
//     "referenced attempt or observation not found" response.
//   - 23514 chk_hypothesis_resolution → ErrEvidenceRequired. Should be
//     unreachable post-handler-validation, but if it fires the handler
//     can return 422 instead of a 500.
//   - 23514 chk_hypothesis_resolved_at → ErrInvalidTransition. Means
//     the (state, resolved_at) pair is inconsistent; structurally
//     impossible from this query but we map it instead of swallowing
//     it into ErrEvidenceRequired, which would lie to the client.
//   - 23514 on any other constraint name → wrapped with context. Never
//     map an unknown CHECK to a specific sentinel — that is how new
//     schema rules start masquerading as old ones.
func (s *Store) UpdateResolution(ctx context.Context, id uuid.UUID, state State, p ResolveParams) (*Record, error) {
	var summary *string
	if trimmed := strings.TrimSpace(p.ResolutionSummary); trimmed != "" {
		summary = &trimmed
	}
	r, err := s.q.UpdateHypothesisResolution(ctx, db.UpdateHypothesisResolutionParams{
		ID:            id,
		State:         db.HypothesisState(state),
		AttemptID:     p.AttemptID,
		ObservationID: p.ObservationID,
		Summary:       summary,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
			switch pgErr.Code {
			case pgerrcode.ForeignKeyViolation:
				return nil, ErrEvidenceNotFound
			case pgerrcode.CheckViolation:
				switch pgErr.ConstraintName {
				case "chk_hypothesis_resolution":
					return nil, ErrEvidenceRequired
				case "chk_hypothesis_resolved_at":
					return nil, ErrInvalidTransition
				}
			}
		}
		return nil, fmt.Errorf("resolving hypothesis %s: %w", id, err)
	}
	return rowToRecord(&r)
}

// UpdateMetadata overwrites a hypothesis's metadata blob.
func (s *Store) UpdateMetadata(ctx context.Context, id uuid.UUID, metadata json.RawMessage) (*Record, error) {
	r, err := s.q.UpdateHypothesisMetadata(ctx, db.UpdateHypothesisMetadataParams{
		ID:       id,
		Metadata: metadata,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating hypothesis %s metadata: %w", id, err)
	}
	return rowToRecord(&r)
}

// AppendEvidence atomically appends a JSON entry to metadata under
// "supporting_evidence" or "counter_evidence". Unlike the read-modify-
// write path through UpdateMetadata, this runs as a single UPDATE so
// concurrent callers cannot lose entries under Read Committed — the DB
// serializes the row update and each request's append is applied to
// the latest metadata value.
//
// evidenceType MUST be "supporting" or "counter"; the handler enforces
// this before the call. entry is the raw JSON object to append and is
// written as-is — the caller is responsible for size bounds and for
// any shape validation.
func (s *Store) AppendEvidence(ctx context.Context, id uuid.UUID, evidenceType string, entry json.RawMessage) (*Record, error) {
	// Wrap the entry in a single-element array so jsonb || jsonb appends
	// one element, not the entry's own fields. E.g. entry={"type":"..."}
	// becomes [{"type":"..."}] before concat.
	wrapped, err := json.Marshal([]json.RawMessage{entry})
	if err != nil {
		return nil, fmt.Errorf("wrapping evidence entry for hypothesis %s: %w", id, err)
	}
	r, err := s.q.AppendHypothesisEvidence(ctx, db.AppendHypothesisEvidenceParams{
		ID:          id,
		EvidenceKey: evidenceType + "_evidence",
		Entry:       wrapped,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("appending evidence to hypothesis %s: %w", id, err)
	}
	return rowToRecord(&r)
}

// Unverified returns up to maxResults unverified hypotheses.
func (s *Store) Unverified(ctx context.Context, maxResults int32) ([]Record, error) {
	rows, err := s.q.UnverifiedHypotheses(ctx, maxResults)
	if err != nil {
		return nil, fmt.Errorf("listing unverified hypotheses: %w", err)
	}
	return rowsToRecords(rows)
}

// ByState returns hypotheses filtered by state (nil = all states).
func (s *Store) ByState(ctx context.Context, state *State, maxResults int32) ([]Record, error) {
	stateArg := db.NullHypothesisState{}
	if state != nil {
		stateArg.HypothesisState = db.HypothesisState(*state)
		stateArg.Valid = true
	}
	rows, err := s.q.HypothesesByState(ctx, db.HypothesesByStateParams{
		State:      stateArg,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing hypotheses by state: %w", err)
	}
	return rowsToRecords(rows)
}

// RecordsPaged returns a paginated list of hypotheses with optional state filter.
func (s *Store) RecordsPaged(ctx context.Context, state *State, page, perPage int) ([]Record, int, error) {
	stateArg := db.NullHypothesisState{}
	if state != nil {
		stateArg.HypothesisState = db.HypothesisState(*state)
		stateArg.Valid = true
	}

	total, err := s.q.HypothesesPagedCount(ctx, stateArg)
	if err != nil {
		return nil, 0, fmt.Errorf("counting hypotheses: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.q.HypothesesPaged(ctx, db.HypothesesPagedParams{
		State:      stateArg,
		PageLimit:  int32(perPage), //nolint:gosec // G115: clamped by api.ParsePagination (max 100)
		PageOffset: int32(offset),  //nolint:gosec // G115: page*perPage bounded by pagination limits
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing hypotheses paged: %w", err)
	}
	out, err := rowsToRecords(rows)
	if err != nil {
		return nil, 0, err
	}
	return out, int(total), nil
}

func rowsToRecords(rows []db.LearningHypothesis) ([]Record, error) {
	out := make([]Record, 0, len(rows))
	for i := range rows {
		rec, err := rowToRecord(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, nil
}

func rowToRecord(r *db.LearningHypothesis) (*Record, error) {
	var meta map[string]any
	if len(r.Metadata) > 0 {
		if err := json.Unmarshal(r.Metadata, &meta); err != nil {
			return nil, fmt.Errorf("unmarshaling hypothesis %s metadata: %w", r.ID, err)
		}
	}
	return &Record{
		ID:                      r.ID,
		CreatedBy:               r.CreatedBy,
		Content:                 r.Content,
		State:                   State(r.State),
		Claim:                   r.Claim,
		InvalidationCondition:   r.InvalidationCondition,
		Metadata:                meta,
		ObservedDate:            r.ObservedDate,
		ResolvedAt:              r.ResolvedAt,
		ResolvedByAttemptID:     r.ResolvedByAttemptID,
		ResolvedByObservationID: r.ResolvedByObservationID,
		ResolutionSummary:       r.ResolutionSummary,
		CreatedAt:               r.CreatedAt,
	}, nil
}
