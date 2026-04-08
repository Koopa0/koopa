package directive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for directives.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store using the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Participant holds resolved participant capabilities.
type Participant struct {
	Name                 string
	CanIssueDirectives   bool
	CanReceiveDirectives bool
	CanWriteReports      bool
	TaskAssignable       bool
}

// ParticipantByName returns a participant's capabilities.
func (s *Store) ParticipantByName(ctx context.Context, name string) (*Participant, error) {
	row, err := s.q.ParticipantByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("participant %q not found: %w", name, err)
	}
	return &Participant{
		Name:                 row.Name,
		CanIssueDirectives:   row.CanIssueDirectives,
		CanReceiveDirectives: row.CanReceiveDirectives,
		CanWriteReports:      row.CanWriteReports,
		TaskAssignable:       row.TaskAssignable,
	}, nil
}

// ValidateCapabilities checks that source can issue and target can receive directives.
func (s *Store) ValidateCapabilities(ctx context.Context, source, target string) error {
	src, err := s.q.ParticipantByName(ctx, source)
	if err != nil {
		return fmt.Errorf("source participant %q not found: %w", source, err)
	}
	if !src.CanIssueDirectives {
		return fmt.Errorf("participant %q cannot issue directives", source)
	}

	tgt, err := s.q.ParticipantByName(ctx, target)
	if err != nil {
		return fmt.Errorf("target participant %q not found: %w", target, err)
	}
	if !tgt.CanReceiveDirectives {
		return fmt.Errorf("participant %q cannot receive directives", target)
	}

	return nil
}

// Create inserts a new directive after validating participant capabilities.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Directive, error) {
	if err := s.ValidateCapabilities(ctx, p.Source, p.Target); err != nil {
		return nil, err
	}

	row, err := s.q.CreateDirective(ctx, db.CreateDirectiveParams{
		Source:     p.Source,
		Target:     p.Target,
		Priority:   p.Priority,
		Content:    p.Content,
		Metadata:   p.Metadata,
		IssuedDate: p.IssuedDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating directive: %w", err)
	}
	return rowToDirective(&row), nil
}

// ByID returns a single directive by ID.
func (s *Store) ByID(ctx context.Context, id int64) (*Directive, error) {
	row, err := s.q.DirectiveByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying directive %d: %w", id, err)
	}
	return rowToDirective(&row), nil
}

// Acknowledge marks a directive as acknowledged by the target.
func (s *Store) Acknowledge(ctx context.Context, id int64, acknowledgedBy string) (*Directive, error) {
	row, err := s.q.AcknowledgeDirective(ctx, db.AcknowledgeDirectiveParams{
		ID:             id,
		AcknowledgedBy: &acknowledgedBy,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("acknowledging directive %d: %w", id, err)
	}
	return rowToDirective(&row), nil
}

// UnackedForTarget returns unacknowledged directives for a participant.
func (s *Store) UnackedForTarget(ctx context.Context, target string) ([]Directive, error) {
	rows, err := s.q.UnackedDirectivesForTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("querying unacked directives for %s: %w", target, err)
	}
	result := make([]Directive, len(rows))
	for i := range rows {
		result[i] = *rowToDirective(&rows[i])
	}
	return result, nil
}

func rowToDirective(r *db.Directive) *Directive {
	d := &Directive{
		ID:                 r.ID,
		Source:             r.Source,
		Target:             r.Target,
		Priority:           r.Priority,
		AcknowledgedAt:     r.AcknowledgedAt,
		AcknowledgedBy:     r.AcknowledgedBy,
		ResolvedAt:         r.ResolvedAt,
		ResolutionReportID: r.ResolutionReportID,
		Content:            r.Content,
		IssuedDate:         r.IssuedDate,
		CreatedAt:          r.CreatedAt,
	}
	if r.Metadata != nil {
		_ = json.Unmarshal(r.Metadata, &d.Metadata)
	}
	return d
}

// Resolve marks a directive as resolved, linking to the resolution report.
func (s *Store) Resolve(ctx context.Context, id int64, reportID *int64) (*Directive, error) {
	row, err := s.q.ResolveDirective(ctx, db.ResolveDirectiveParams{
		ID:                 id,
		ResolutionReportID: reportID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resolving directive %d: %w", id, err)
	}
	return rowToDirective(&row), nil
}

// UnresolvedForTarget returns acknowledged but unresolved directives for a participant.
func (s *Store) UnresolvedForTarget(ctx context.Context, target string) ([]Directive, error) {
	rows, err := s.q.UnresolvedDirectivesForTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("querying unresolved directives for %s: %w", target, err)
	}
	result := make([]Directive, len(rows))
	for i := range rows {
		result[i] = *rowToDirective(&rows[i])
	}
	return result, nil
}
