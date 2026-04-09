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

	"github.com/Koopa0/koopa0.dev/internal/db"
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

// AddItemParams holds the input for adding an item to a plan.
type AddItemParams struct {
	PlanID         uuid.UUID
	LearningItemID uuid.UUID
	Position       int32
	Phase          *string
}

// UpdateItemStatusParams holds the input for updating a plan item's status.
type UpdateItemStatusParams struct {
	ID                   uuid.UUID
	Status               ItemStatus
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

// ActivePlans returns all plans with status "active".
func (s *Store) ActivePlans(ctx context.Context) ([]Plan, error) {
	rows, err := s.q.ActivePlans(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying active plans: %w", err)
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

// AddItem adds a learning item to a plan. Validates position (≥ 0) and phase if non-nil.
func (s *Store) AddItem(ctx context.Context, p AddItemParams) (*PlanItem, error) {
	if p.Position < 0 {
		return nil, fmt.Errorf("position must be >= 0, got %d", p.Position)
	}
	if p.Phase != nil {
		if err := ValidatePhase(*p.Phase); err != nil {
			return nil, err
		}
	}

	row, err := s.q.AddPlanItem(ctx, db.AddPlanItemParams{
		PlanID:         p.PlanID,
		LearningItemID: p.LearningItemID,
		Position:       p.Position,
		Phase:          p.Phase,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("adding plan item: %w", err)
	}
	return rowToItem(&row), nil
}

// Item returns a single plan item by ID.
func (s *Store) Item(ctx context.Context, id uuid.UUID) (*PlanItem, error) {
	row, err := s.q.PlanItem(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying plan item %s: %w", id, err)
	}
	return rowToItem(&row), nil
}

// Items returns all items for a plan, ordered by position.
func (s *Store) Items(ctx context.Context, planID uuid.UUID) ([]PlanItem, error) {
	rows, err := s.q.PlanItems(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("querying plan items for plan %s: %w", planID, err)
	}
	result := make([]PlanItem, len(rows))
	for i := range rows {
		result[i] = *rowToItem(&rows[i])
	}
	return result, nil
}

// ItemsByLearningItem returns plan items across active plans that reference
// the given learning item, including the parent plan's title.
func (s *Store) ItemsByLearningItem(ctx context.Context, learningItemID uuid.UUID) ([]PlanItemWithTitle, error) {
	rows, err := s.q.PlanItemsByLearningItem(ctx, learningItemID)
	if err != nil {
		return nil, fmt.Errorf("querying plan items by learning item %s: %w", learningItemID, err)
	}
	result := make([]PlanItemWithTitle, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = PlanItemWithTitle{
			PlanItem: PlanItem{
				ID:                   r.ID,
				PlanID:               r.PlanID,
				LearningItemID:       r.LearningItemID,
				Position:             r.Position,
				Status:               ItemStatus(r.Status),
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

// UpdateItemStatus transitions a plan item to a new status.
func (s *Store) UpdateItemStatus(ctx context.Context, p UpdateItemStatusParams) (*PlanItem, error) {
	row, err := s.q.UpdatePlanItemStatus(ctx, db.UpdatePlanItemStatusParams{
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
		return nil, fmt.Errorf("updating plan item status %s: %w", p.ID, err)
	}
	return rowToItem(&row), nil
}

// UpdateItemPosition changes the position of a plan item.
func (s *Store) UpdateItemPosition(ctx context.Context, itemID uuid.UUID, position int32) error {
	n, err := s.q.UpdatePlanItemPosition(ctx, db.UpdatePlanItemPositionParams{
		Position: position,
		ID:       itemID,
	})
	if err != nil {
		return fmt.Errorf("updating plan item position %s: %w", itemID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveItems deletes plan items by plan ID and item IDs.
func (s *Store) RemoveItems(ctx context.Context, planID uuid.UUID, itemIDs []uuid.UUID) error {
	err := s.q.DeletePlanItems(ctx, db.DeletePlanItemsParams{
		PlanID:  planID,
		ItemIds: itemIDs,
	})
	if err != nil {
		return fmt.Errorf("removing plan items from plan %s: %w", planID, err)
	}
	return nil
}

// Progress returns aggregate completion counts for a plan's items.
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

// ItemsDetailed returns plan items joined with learning item display fields,
// ordered by position. This is the read path for manage_plan(progress) when
// callers need plan_item_id plus the parent item's title/domain/difficulty.
func (s *Store) ItemsDetailed(ctx context.Context, planID uuid.UUID) ([]PlanItemDetail, error) {
	rows, err := s.q.PlanItemsDetailed(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("querying detailed plan items for %s: %w", planID, err)
	}
	out := make([]PlanItemDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = PlanItemDetail{
			PlanItemID:           r.ID,
			PlanID:               r.PlanID,
			LearningItemID:       r.LearningItemID,
			Position:             r.Position,
			Status:               ItemStatus(r.Status),
			Phase:                r.Phase,
			SubstitutedBy:        r.SubstitutedBy,
			CompletedByAttemptID: r.CompletedByAttemptID,
			Reason:               r.Reason,
			AddedAt:              r.AddedAt,
			CompletedAt:          r.CompletedAt,
			ItemTitle:            r.ItemTitle,
			ItemDomain:           r.ItemDomain,
			ItemDifficulty:       r.ItemDifficulty,
			ItemExternalID:       r.ItemExternalID,
		}
	}
	return out, nil
}

func rowToPlan(r *db.Plan) *Plan {
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

func rowToItem(r *db.PlanItem) *PlanItem {
	return &PlanItem{
		ID:                   r.ID,
		PlanID:               r.PlanID,
		LearningItemID:       r.LearningItemID,
		Position:             r.Position,
		Status:               ItemStatus(r.Status),
		Phase:                r.Phase,
		SubstitutedBy:        r.SubstitutedBy,
		CompletedByAttemptID: r.CompletedByAttemptID,
		Reason:               r.Reason,
		AddedAt:              r.AddedAt,
		CompletedAt:          r.CompletedAt,
	}
}

func rowsToPlans(rows []db.Plan) []Plan {
	result := make([]Plan, len(rows))
	for i := range rows {
		result[i] = *rowToPlan(&rows[i])
	}
	return result
}
