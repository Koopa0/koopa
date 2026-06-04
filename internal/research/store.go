// Copyright 2026 Koopa. All rights reserved.

package research

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for research assignments and reports.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by the MCP layer's
// withActorTx so the report insert and the assignment-fulfillment update share
// one transaction (and carry koopa.actor for audit attribution).
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// CreateAssignment dispatches a fan-out research assignment. assigned_to and
// assigned_by are FK-checked against agents — an unknown name returns
// ErrUnknownAgent.
func (s *Store) CreateAssignment(ctx context.Context, p CreateAssignmentParams) (*Assignment, error) {
	r, err := s.q.CreateAssignment(ctx, db.CreateAssignmentParams{
		Topic:      p.Topic,
		AssignedTo: p.AssignedTo,
		AssignedBy: p.AssignedBy,
	})
	if err != nil {
		if isFKViolation(err) {
			return nil, fmt.Errorf("%w: assigned_to=%q assigned_by=%q", ErrUnknownAgent, p.AssignedTo, p.AssignedBy)
		}
		return nil, fmt.Errorf("creating research assignment: %w", err)
	}
	return buildAssignment(&r), nil
}

// Assignment returns a single assignment by ID.
func (s *Store) Assignment(ctx context.Context, id uuid.UUID) (*Assignment, error) {
	r, err := s.q.AssignmentByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying assignment %s: %w", id, err)
	}
	return buildAssignment(&r), nil
}

// OpenAssignments returns unfulfilled assignments newest-first, capped by limit.
// It is the store-level read for unfulfilled work: an assignment sits here until
// a report fulfills it. No agent-facing MCP tool surfaces this yet — it is the
// query a future open-assignments read/admin surface will build on.
func (s *Store) OpenAssignments(ctx context.Context, limit int) ([]Assignment, error) {
	rows, err := s.q.OpenAssignments(ctx, int32(limit)) // #nosec G115 -- limit bounded by caller
	if err != nil {
		return nil, fmt.Errorf("listing open assignments: %w", err)
	}
	out := make([]Assignment, 0, len(rows))
	for i := range rows {
		out = append(out, *buildAssignment(&rows[i]))
	}
	return out, nil
}

// CreateReport inserts a report. When OriginAssignmentID is set, the report is
// the fulfillment of that assignment: the same call flips the assignment
// open → fulfilled (idempotent — only an open assignment transitions). Callers
// that want the insert and the fulfillment to be atomic must invoke this via
// WithTx(tx); the MCP handler does so through withActorTx.
//
// trust_status is never a parameter — every report is born low_trust.
func (s *Store) CreateReport(ctx context.Context, p CreateReportParams) (*Report, error) {
	r, err := s.q.CreateReport(ctx, db.CreateReportParams{
		Title:              p.Title,
		Body:               p.Body,
		ProducedBy:         p.ProducedBy,
		OriginAssignmentID: p.OriginAssignmentID,
	})
	if err != nil {
		if isFKViolation(err) {
			// produced_by → agents, or origin_assignment_id → research_assignments.
			if fkConstraintMentions(err, "origin_assignment") {
				return nil, fmt.Errorf("%w: origin_assignment_id", ErrNotFound)
			}
			return nil, fmt.Errorf("%w: produced_by=%q", ErrUnknownAgent, p.ProducedBy)
		}
		return nil, fmt.Errorf("creating report: %w", err)
	}

	if p.OriginAssignmentID != nil {
		// Fulfill the originating assignment in the same (caller-controlled)
		// transaction. rows==0 means it was already fulfilled — acceptable; the
		// report still stands.
		if _, fErr := s.q.FulfillAssignment(ctx, *p.OriginAssignmentID); fErr != nil {
			return nil, fmt.Errorf("fulfilling assignment %s: %w", *p.OriginAssignmentID, fErr)
		}
	}

	return buildReport(
		r.ID, r.Title, r.Body, r.ProducedBy,
		r.OriginAssignmentID, r.TrustStatus, r.CreatedAt, r.UpdatedAt,
	), nil
}

// Report returns a single report by ID.
func (s *Store) Report(ctx context.Context, id uuid.UUID) (*Report, error) {
	r, err := s.q.ReportByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying report %s: %w", id, err)
	}
	return buildReport(
		r.ID, r.Title, r.Body, r.ProducedBy,
		r.OriginAssignmentID, r.TrustStatus, r.CreatedAt, r.UpdatedAt,
	), nil
}

// Search performs a full-text search over reports (title + body), relevance
// ordered, capped by limit. Empty query returns no results.
func (s *Store) Search(ctx context.Context, query string, limit int) ([]Report, error) {
	if query == "" {
		return nil, nil
	}
	rows, err := s.q.SearchReports(ctx, db.SearchReportsParams{
		Query:      query,
		MaxResults: int32(limit), // #nosec G115 -- limit bounded by MCP handler
	})
	if err != nil {
		return nil, fmt.Errorf("searching reports: %w", err)
	}
	out := make([]Report, 0, len(rows))
	for i := range rows {
		out = append(out, *buildReport(
			rows[i].ID, rows[i].Title, rows[i].Body, rows[i].ProducedBy,
			rows[i].OriginAssignmentID, rows[i].TrustStatus, rows[i].CreatedAt, rows[i].UpdatedAt,
		))
	}
	return out, nil
}

// SetTrust promotes or demotes a report's trust status. This is the backend for
// the human/admin trust verdict — it is deliberately NOT exposed as an
// agent-facing MCP tool. It is schema/store-ready but no production human UI
// consumes it yet (deferred), so every report stays low_trust in practice until
// that surface lands. Returns ErrNotFound when no row matched and ErrInvalidTrust
// on an unrecognized status.
func (s *Store) SetTrust(ctx context.Context, id uuid.UUID, t TrustStatus) (*Report, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidTrust, t)
	}
	r, err := s.q.SetReportTrust(ctx, db.SetReportTrustParams{
		ID:          id,
		TrustStatus: string(t),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("setting trust on report %s: %w", id, err)
	}
	return buildReport(
		r.ID, r.Title, r.Body, r.ProducedBy,
		r.OriginAssignmentID, r.TrustStatus, r.CreatedAt, r.UpdatedAt,
	), nil
}

// buildReport converts the flat tuple of report row fields (sqlc emits a
// distinct row type per query, all sharing these fields) into the domain Report.
func buildReport(
	id uuid.UUID,
	title, body, producedBy string,
	originAssignmentID *uuid.UUID,
	trustStatus string,
	createdAt, updatedAt time.Time,
) *Report {
	return &Report{
		ID:                 id,
		Title:              title,
		Body:               body,
		ProducedBy:         producedBy,
		OriginAssignmentID: originAssignmentID,
		TrustStatus:        TrustStatus(trustStatus),
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
	}
}

// buildAssignment converts a db.ResearchAssignment into the domain Assignment.
func buildAssignment(r *db.ResearchAssignment) *Assignment {
	return &Assignment{
		ID:          r.ID,
		Topic:       r.Topic,
		AssignedTo:  r.AssignedTo,
		AssignedBy:  r.AssignedBy,
		Status:      Status(r.Status),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		FulfilledAt: r.FulfilledAt,
	}
}

// isFKViolation reports whether err is a PostgreSQL foreign-key violation.
func isFKViolation(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == pgerrcode.ForeignKeyViolation
}

// fkConstraintMentions reports whether err is an FK violation whose constraint
// name contains sub — used to distinguish which FK failed.
func fkConstraintMentions(err error, sub string) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && strings.Contains(pgErr.ConstraintName, sub)
}
