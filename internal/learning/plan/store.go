package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// CreatePlanParams holds the input for creating a new learning plan.
type CreatePlanParams struct {
	Title       string
	Description string
	Domain      string
	GoalID      *uuid.UUID
	TargetCount *int32
	PlanConfig  json.RawMessage
	CreatedBy   string
}

// AddEntryParams holds the input for adding an entry to a plan.
type AddEntryParams struct {
	PlanID           uuid.UUID
	LearningTargetID uuid.UUID
	Position         int32
	Phase            *string
}

// UpdateEntryStatusParams holds the input for updating a plan entry's status.
type UpdateEntryStatusParams struct {
	ID                   uuid.UUID
	Status               EntryStatus
	Reason               *string
	CompletedAt          *time.Time
	SubstitutedBy        *uuid.UUID
	CompletedByAttemptID *uuid.UUID
}

// Store handles database operations for learning plans.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store that uses the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// CreatePlan inserts a new learning plan with status "draft".
func (s *Store) CreatePlan(ctx context.Context, p *CreatePlanParams) (*Plan, error) {
	config := p.PlanConfig
	if config == nil {
		config = json.RawMessage("{}")
	}

	row, err := s.q.CreatePlan(ctx, db.CreatePlanParams{
		Title:       p.Title,
		Description: p.Description,
		Domain:      p.Domain,
		GoalID:      p.GoalID,
		Status:      string(StatusDraft),
		TargetCount: p.TargetCount,
		PlanConfig:  config,
		CreatedBy:   p.CreatedBy,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating plan: %w", err)
	}
	return rowToPlan(&row), nil
}

// Plan returns a single plan by ID.
func (s *Store) Plan(ctx context.Context, id uuid.UUID) (*Plan, error) {
	row, err := s.q.Plan(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying plan %s: %w", id, err)
	}
	return rowToPlan(&row), nil
}

// PlansByDomain returns plans filtered by domain and optionally by status.
func (s *Store) PlansByDomain(ctx context.Context, domain string, status *string) ([]Plan, error) {
	rows, err := s.q.PlansByDomain(ctx, db.PlansByDomainParams{
		Domain: domain,
		Status: status,
	})
	if err != nil {
		return nil, fmt.Errorf("querying plans by domain %s: %w", domain, err)
	}
	return rowsToPlans(rows), nil
}

// PlansByGoal returns all plans linked to a specific goal.
func (s *Store) PlansByGoal(ctx context.Context, goalID uuid.UUID) ([]Plan, error) {
	rows, err := s.q.PlansByGoal(ctx, &goalID)
	if err != nil {
		return nil, fmt.Errorf("querying plans by goal %s: %w", goalID, err)
	}
	return rowsToPlans(rows), nil
}

// PlansInManagement returns all plans visible to the management UI —
// status in ('draft', 'active').
// entry: the old name misrepresented the query body, which always
// included draft plans.
func (s *Store) PlansInManagement(ctx context.Context) ([]Plan, error) {
	rows, err := s.q.PlansInManagement(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying plans in management: %w", err)
	}
	return rowsToPlans(rows), nil
}

// UpdatePlanStatus transitions a plan to the given status.
func (s *Store) UpdatePlanStatus(ctx context.Context, id uuid.UUID, status Status) (*Plan, error) {
	row, err := s.q.UpdatePlanStatus(ctx, db.UpdatePlanStatusParams{
		Status: string(status),
		ID:     id,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating plan status %s: %w", id, err)
	}
	return rowToPlan(&row), nil
}

// AddEntry adds a learning target to a plan. Validates position (≥ 0) and phase if non-nil.
func (s *Store) AddEntry(ctx context.Context, p AddEntryParams) (*Entry, error) {
	if p.Position < 0 {
		return nil, fmt.Errorf("position must be >= 0, got %d", p.Position)
	}
	if p.Phase != nil {
		if err := ValidatePhase(*p.Phase); err != nil {
			return nil, err
		}
	}

	row, err := s.q.AddPlanEntry(ctx, db.AddPlanEntryParams{
		PlanID:           p.PlanID,
		LearningTargetID: p.LearningTargetID,
		Position:         p.Position,
		Phase:            p.Phase,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("adding plan entry: %w", err)
	}
	return rowToEntry(&row), nil
}

// Entry returns a single plan entry by ID.
func (s *Store) Entry(ctx context.Context, id uuid.UUID) (*Entry, error) {
	row, err := s.q.PlanEntry(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying plan entry %s: %w", id, err)
	}
	return rowToEntry(&row), nil
}

// Entries returns all entries for a plan, ordered by position.
func (s *Store) Entries(ctx context.Context, planID uuid.UUID) ([]Entry, error) {
	rows, err := s.q.PlanEntries(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("querying plan entries for plan %s: %w", planID, err)
	}
	result := make([]Entry, len(rows))
	for i := range rows {
		result[i] = *rowToEntry(&rows[i])
	}
	return result, nil
}

// EntriesByLearningTarget returns plan entries across active plans that reference
// the given learning target, including the parent plan's title.
func (s *Store) EntriesByLearningTarget(ctx context.Context, learningTargetID uuid.UUID) ([]EntryWithTitle, error) {
	rows, err := s.q.PlanEntriesByLearningTarget(ctx, learningTargetID)
	if err != nil {
		return nil, fmt.Errorf("querying plan entries by learning target %s: %w", learningTargetID, err)
	}
	result := make([]EntryWithTitle, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = EntryWithTitle{
			Entry: Entry{
				ID:                   r.ID,
				PlanID:               r.PlanID,
				LearningTargetID:     r.LearningTargetID,
				Position:             r.Position,
				Status:               EntryStatus(r.Status),
				Phase:                r.Phase,
				SubstitutedBy:        r.SubstitutedBy,
				CompletedByAttemptID: r.CompletedByAttemptID,
				Reason:               r.Reason,
				AddedAt:              r.AddedAt,
				CompletedAt:          r.CompletedAt,
			},
			PlanTitle: r.PlanTitle,
		}
	}
	return result, nil
}

// UpdateEntryStatus transitions a plan entry to a new status.
func (s *Store) UpdateEntryStatus(ctx context.Context, p UpdateEntryStatusParams) (*Entry, error) {
	row, err := s.q.UpdatePlanEntryStatus(ctx, db.UpdatePlanEntryStatusParams{
		Status:               string(p.Status),
		Reason:               p.Reason,
		CompletedAt:          p.CompletedAt,
		SubstitutedBy:        p.SubstitutedBy,
		CompletedByAttemptID: p.CompletedByAttemptID,
		ID:                   p.ID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating plan entry status %s: %w", p.ID, err)
	}
	return rowToEntry(&row), nil
}

// UpdateEntryPosition changes the position of a plan entry.
func (s *Store) UpdateEntryPosition(ctx context.Context, entryID uuid.UUID, position int32) error {
	n, err := s.q.UpdatePlanEntryPosition(ctx, db.UpdatePlanEntryPositionParams{
		Position: position,
		ID:       entryID,
	})
	if err != nil {
		return fmt.Errorf("updating plan entry position %s: %w", entryID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveEntries deletes plan entries by plan ID and entry IDs.
func (s *Store) RemoveEntries(ctx context.Context, planID uuid.UUID, entryIDs []uuid.UUID) error {
	err := s.q.DeletePlanEntries(ctx, db.DeletePlanEntriesParams{
		PlanID:   planID,
		EntryIds: entryIDs,
	})
	if err != nil {
		return fmt.Errorf("removing plan entries from plan %s: %w", planID, err)
	}
	return nil
}

// Progress returns aggregate completion counts for a plan's entries.
func (s *Store) Progress(ctx context.Context, planID uuid.UUID) (*Progress, error) {
	row, err := s.q.PlanProgress(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("querying plan progress %s: %w", planID, err)
	}
	return &Progress{
		Total:       row.Total,
		Completed:   row.Completed,
		Skipped:     row.Skipped,
		Substituted: row.Substituted,
		Remaining:   row.Remaining,
	}, nil
}

// EntriesDetailed returns plan entries joined with learning target display fields,
// ordered by position. This is the read path for manage_plan(progress) when
// callers need plan_entry_id plus the parent target's title/domain/difficulty.
func (s *Store) EntriesDetailed(ctx context.Context, planID uuid.UUID) ([]EntryDetail, error) {
	rows, err := s.q.PlanEntriesDetailed(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("querying detailed plan entries for %s: %w", planID, err)
	}
	out := make([]EntryDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = EntryDetail{
			PlanEntryID:          r.ID,
			PlanID:               r.PlanID,
			LearningTargetID:     r.LearningTargetID,
			Position:             r.Position,
			Status:               EntryStatus(r.Status),
			Phase:                r.Phase,
			SubstitutedBy:        r.SubstitutedBy,
			CompletedByAttemptID: r.CompletedByAttemptID,
			Reason:               r.Reason,
			AddedAt:              r.AddedAt,
			CompletedAt:          r.CompletedAt,
			TargetTitle:          r.TargetTitle,
			TargetDomain:         r.TargetDomain,
			TargetDifficulty:     r.TargetDifficulty,
			TargetExternalID:     r.TargetExternalID,
		}
	}
	return out, nil
}

func rowToPlan(r *db.LearningPlan) *Plan {
	return &Plan{
		ID:          r.ID,
		Title:       r.Title,
		Description: r.Description,
		Domain:      r.Domain,
		GoalID:      r.GoalID,
		Status:      Status(r.Status),
		TargetCount: r.TargetCount,
		PlanConfig:  r.PlanConfig,
		CreatedBy:   r.CreatedBy,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func rowToEntry(r *db.LearningPlanEntry) *Entry {
	return &Entry{
		ID:                   r.ID,
		PlanID:               r.PlanID,
		LearningTargetID:     r.LearningTargetID,
		Position:             r.Position,
		Status:               EntryStatus(r.Status),
		Phase:                r.Phase,
		SubstitutedBy:        r.SubstitutedBy,
		CompletedByAttemptID: r.CompletedByAttemptID,
		Reason:               r.Reason,
		AddedAt:              r.AddedAt,
		CompletedAt:          r.CompletedAt,
	}
}

func rowsToPlans(rows []db.LearningPlan) []Plan {
	result := make([]Plan, len(rows))
	for i := range rows {
		result[i] = *rowToPlan(&rows[i])
	}
	return result
}
