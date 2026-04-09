package learning

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
	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for learning sessions, attempts, observations, and FSRS review cards.
type Store struct {
	q     *db.Queries
	sched *scheduler
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx), sched: newScheduler()}
}

// WithTx returns a new Store using the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx), sched: s.sched}
}

// StartSession creates a new learning session. Fails if an active session exists.
func (s *Store) StartSession(ctx context.Context, domain string, mode Mode, dailyPlanItemID *uuid.UUID) (*Session, error) {
	// Check for active session.
	if _, err := s.q.ActiveSession(ctx); err == nil {
		return nil, ErrActiveExists
	}

	row, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		Domain:          domain,
		SessionMode:     string(mode),
		DailyPlanItemID: dailyPlanItemID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	return rowToSession(&row), nil
}

// ActiveSession returns the currently active session, or ErrNoActive.
func (s *Store) ActiveSession(ctx context.Context) (*Session, error) {
	row, err := s.q.ActiveSession(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoActive
		}
		return nil, fmt.Errorf("querying active session: %w", err)
	}
	return rowToSession(&row), nil
}

// EndSession ends the active session. Optionally links a journal entry.
func (s *Store) EndSession(ctx context.Context, sessionID uuid.UUID, journalID *int64) (*Session, error) {
	row, err := s.q.EndSession(ctx, db.EndSessionParams{
		ID:        sessionID,
		JournalID: journalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAlreadyEnded
		}
		return nil, fmt.Errorf("ending session: %w", err)
	}
	return rowToSession(&row), nil
}

// FindOrCreateItem upserts a learning item by domain + external_id (or title).
func (s *Store) FindOrCreateItem(ctx context.Context, domain, title string, externalID, difficulty *string) (uuid.UUID, error) {
	row, err := s.q.FindOrCreateItem(ctx, db.FindOrCreateItemParams{
		Domain:     domain,
		Title:      title,
		ExternalID: externalID,
		Difficulty: difficulty,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("finding/creating learning item: %w", err)
	}
	return row.ID, nil
}

// RelationType is a learning item relationship kind — must match the
// item_relations.relation_type CHECK constraint in migration 001.
type RelationType string

// item_relations.relation_type allowed values.
const (
	RelationEasierVariant    RelationType = "easier_variant"
	RelationHarderVariant    RelationType = "harder_variant"
	RelationPrerequisite     RelationType = "prerequisite"
	RelationFollowUp         RelationType = "follow_up"
	RelationSamePattern      RelationType = "same_pattern"
	RelationSimilarStructure RelationType = "similar_structure"
)

var validRelationTypes = map[RelationType]struct{}{
	RelationEasierVariant:    {},
	RelationHarderVariant:    {},
	RelationPrerequisite:     {},
	RelationFollowUp:         {},
	RelationSamePattern:      {},
	RelationSimilarStructure: {},
}

// ValidRelationType reports whether r is a supported relation type.
func ValidRelationType(r RelationType) bool {
	_, ok := validRelationTypes[r]
	return ok
}

// LinkItems inserts an item_relations row from sourceID to targetID with
// relation. Enforces the invariants LinkItems owns:
//   - sourceID != targetID
//   - relation is in the allowlist
//
// Cross-domain rejection is NOT enforced here. The caller already has the
// source domain in scope and resolves the target via FindOrCreateItem, which
// bakes the domain into the row — a domain check here would be two extra
// round-trips per attempt for a rule the caller can check locally. The
// caller is expected to pre-validate same-domain before calling LinkItems.
//
// Idempotent: conflicts on (source, target, relation) are ignored so the
// same pair can be re-linked from a later session without error.
func (s *Store) LinkItems(ctx context.Context, sourceID, targetID uuid.UUID, relation RelationType) error {
	if sourceID == targetID {
		return fmt.Errorf("%w: cannot link item %s to itself", ErrInvalidInput, sourceID)
	}
	if !ValidRelationType(relation) {
		return fmt.Errorf("%w: unknown relation_type %q", ErrInvalidInput, relation)
	}
	if err := s.q.InsertItemRelation(ctx, db.InsertItemRelationParams{
		SourceItemID: sourceID,
		TargetItemID: targetID,
		RelationType: string(relation),
	}); err != nil {
		return fmt.Errorf("inserting item relation: %w", err)
	}
	return nil
}

// RecordAttempt creates an attempt and returns it.
func (s *Store) RecordAttempt(ctx context.Context, itemID, sessionID uuid.UUID, outcome string, durationMin *int32, stuckAt, approachUsed *string, metadata json.RawMessage) (*Attempt, error) {
	// Get next attempt number.
	maxNum, err := s.q.AttemptCountForItem(ctx, itemID)
	if err != nil {
		return nil, fmt.Errorf("counting attempts: %w", err)
	}

	if metadata == nil {
		metadata = json.RawMessage("{}")
	}
	row, err := s.q.CreateAttempt(ctx, db.CreateAttemptParams{
		LearningItemID:  itemID,
		SessionID:       &sessionID,
		AttemptNumber:   maxNum + 1,
		Outcome:         outcome,
		DurationMinutes: durationMin,
		StuckAt:         stuckAt,
		ApproachUsed:    approachUsed,
		Metadata:        metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("creating attempt: %w", err)
	}
	return &Attempt{
		ID:              row.ID,
		ItemID:          row.LearningItemID,
		SessionID:       row.SessionID,
		AttemptNumber:   row.AttemptNumber,
		Outcome:         row.Outcome,
		DurationMinutes: row.DurationMinutes,
		StuckAt:         row.StuckAt,
		ApproachUsed:    row.ApproachUsed,
		AttemptedAt:     row.AttemptedAt,
	}, nil
}

// RecordObservation creates an observation linking an attempt to a concept.
func (s *Store) RecordObservation(ctx context.Context, attemptID, conceptID uuid.UUID, signalType, category string, severity, detail *string) (*Observation, error) {
	row, err := s.q.CreateObservation(ctx, db.CreateObservationParams{
		AttemptID:  attemptID,
		ConceptID:  conceptID,
		SignalType: signalType,
		Category:   category,
		Severity:   severity,
		Detail:     detail,
	})
	if err != nil {
		return nil, fmt.Errorf("creating observation: %w", err)
	}
	return &Observation{
		ID:         row.ID,
		AttemptID:  row.AttemptID,
		ConceptID:  row.ConceptID,
		SignalType: row.SignalType,
		Category:   row.Category,
		Severity:   row.Severity,
		Detail:     row.Detail,
	}, nil
}

// FindOrCreateConcept upserts a concept by domain + slug.
func (s *Store) FindOrCreateConcept(ctx context.Context, slug, name, domain, kind string) (uuid.UUID, error) {
	row, err := s.q.FindOrCreateConcept(ctx, db.FindOrCreateConceptParams{
		Slug:   slug,
		Name:   name,
		Domain: domain,
		Kind:   kind,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("finding/creating concept: %w", err)
	}
	return row.ID, nil
}

// AttemptsBySession returns all attempts for a session with item details.
func (s *Store) AttemptsBySession(ctx context.Context, sessionID uuid.UUID) ([]Attempt, error) {
	rows, err := s.q.AttemptsBySession(ctx, &sessionID)
	if err != nil {
		return nil, fmt.Errorf("querying attempts for session %s: %w", sessionID, err)
	}
	result := make([]Attempt, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = Attempt{
			ID:              r.ID,
			ItemID:          r.LearningItemID,
			SessionID:       r.SessionID,
			AttemptNumber:   r.AttemptNumber,
			Outcome:         r.Outcome,
			DurationMinutes: r.DurationMinutes,
			StuckAt:         r.StuckAt,
			ApproachUsed:    r.ApproachUsed,
			AttemptedAt:     r.AttemptedAt,
			ItemTitle:       r.ItemTitle,
			ItemExternalID:  r.ItemExternalID,
		}
	}
	return result, nil
}

// RecentSessions returns recent sessions, optionally filtered by domain.
func (s *Store) RecentSessions(ctx context.Context, domain *string, since time.Time, limit int32) ([]Session, error) {
	rows, err := s.q.RecentSessions(ctx, db.RecentSessionsParams{
		Domain:     domain,
		Since:      since,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent sessions: %w", err)
	}
	result := make([]Session, len(rows))
	for i := range rows {
		result[i] = *rowToSession(&rows[i])
	}
	return result, nil
}

// ConceptMasteryRow represents per-concept mastery with signal counts.
// Timestamps are non-null by construction: the ConceptMastery SQL query uses
// INNER JOINs against attempt_observations, so every returned row has at
// least one observation in the window and MIN/MAX(created_at) cannot be NULL.
// If that query ever switches to LEFT JOIN, these must become pointers.
type ConceptMasteryRow struct {
	ID                uuid.UUID `json:"id"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	Domain            string    `json:"domain"`
	Kind              string    `json:"kind"`
	WeaknessCount     int64     `json:"weakness_count"`
	ImprovementCount  int64     `json:"improvement_count"`
	MasteryCount      int64     `json:"mastery_count"`
	TotalObservations int64     `json:"total_observations"`
	FirstObservedAt   time.Time `json:"first_observed_at"`
	LastObservedAt    time.Time `json:"last_observed_at"`
}

// ConceptMastery returns per-concept mastery with signal counts and
// first/last observation timestamps. Rows contain only concepts with at
// least one observation in the window — unexplored concepts are not
// returned. Presentation-layer formatting (e.g. mastery stage derivation)
// belongs to the caller, not this store.
func (s *Store) ConceptMastery(ctx context.Context, domain *string, since time.Time) ([]ConceptMasteryRow, error) {
	rows, err := s.q.ConceptMastery(ctx, db.ConceptMasteryParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying concept mastery: %w", err)
	}
	result := make([]ConceptMasteryRow, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptMasteryRow{
			ID:                r.ID,
			Slug:              r.Slug,
			Name:              r.Name,
			Domain:            r.Domain,
			Kind:              r.Kind,
			WeaknessCount:     r.WeaknessCount,
			ImprovementCount:  r.ImprovementCount,
			MasteryCount:      r.MasteryCount,
			TotalObservations: r.TotalObservations,
			FirstObservedAt:   r.FirstObservedAt,
			LastObservedAt:    r.LastObservedAt,
		}
	}
	return result, nil
}

// WeaknessRow represents a cross-pattern weakness analysis row.
// LastSeenAt is the most recent attempt_observation timestamp for this
// concept/category — used by the admin handler to compute days_since_practice.
type WeaknessRow struct {
	ConceptSlug     string    `json:"concept_slug"`
	ConceptName     string    `json:"concept_name"`
	Domain          string    `json:"domain"`
	Category        string    `json:"category"`
	OccurrenceCount int64     `json:"occurrence_count"`
	CriticalCount   int64     `json:"critical_count"`
	ModerateCount   int64     `json:"moderate_count"`
	MinorCount      int64     `json:"minor_count"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

// WeaknessAnalysis returns cross-pattern weakness analysis.
func (s *Store) WeaknessAnalysis(ctx context.Context, domain *string, since time.Time) ([]WeaknessRow, error) {
	rows, err := s.q.WeaknessAnalysis(ctx, db.WeaknessAnalysisParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying weakness analysis: %w", err)
	}
	result := make([]WeaknessRow, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = WeaknessRow{
			ConceptSlug:     r.ConceptSlug,
			ConceptName:     r.ConceptName,
			Domain:          r.Domain,
			Category:        r.Category,
			OccurrenceCount: r.OccurrenceCount,
			CriticalCount:   r.CriticalCount,
			ModerateCount:   r.ModerateCount,
			MinorCount:      r.MinorCount,
			LastSeenAt:      r.LastSeenAt,
		}
	}
	return result, nil
}

// RetrievalItem represents an item due for spaced review.
type RetrievalItem struct {
	CardID     int64     `json:"card_id"`
	Due        time.Time `json:"due"`
	ItemID     uuid.UUID `json:"item_id"`
	Title      string    `json:"title"`
	Domain     string    `json:"domain"`
	Difficulty *string   `json:"difficulty,omitempty"`
	ExternalID *string   `json:"external_id,omitempty"`
}

// RetrievalQueue returns items due for spaced review.
func (s *Store) RetrievalQueue(ctx context.Context, domain *string, dueBefore time.Time, limit int32) ([]RetrievalItem, error) {
	rows, err := s.q.RetrievalQueue(ctx, db.RetrievalQueueParams{
		DueBefore:  dueBefore,
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying retrieval queue: %w", err)
	}
	result := make([]RetrievalItem, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = RetrievalItem{
			CardID:     r.CardID,
			Due:        r.Due,
			ItemID:     r.ItemID,
			Title:      r.Title,
			Domain:     r.Domain,
			Difficulty: r.Difficulty,
			ExternalID: r.ExternalID,
		}
	}
	return result, nil
}

// TimelineSession represents a session with attempt stats for the timeline view.
type TimelineSession struct {
	ID           uuid.UUID  `json:"id"`
	Domain       string     `json:"domain"`
	Mode         string     `json:"mode"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	AttemptCount int64      `json:"attempt_count"`
	SuccessCount int64      `json:"success_count"`
}

// SessionTimeline returns recent sessions with attempt counts for the timeline view.
func (s *Store) SessionTimeline(ctx context.Context, domain *string, since time.Time) ([]TimelineSession, error) {
	rows, err := s.q.SessionTimeline(ctx, db.SessionTimelineParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying session timeline: %w", err)
	}
	result := make([]TimelineSession, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = TimelineSession{
			ID:           r.ID,
			Domain:       r.Domain,
			Mode:         r.SessionMode,
			StartedAt:    r.StartedAt,
			EndedAt:      r.EndedAt,
			AttemptCount: r.AttemptCount,
			SuccessCount: r.SuccessCount,
		}
	}
	return result, nil
}

// ItemRelation represents a relationship between two learning items.
type ItemRelation struct {
	RelationID   uuid.UUID `json:"relation_id"`
	RelationType string    `json:"relation_type"`
	SourceID     uuid.UUID `json:"source_id"`
	SourceTitle  string    `json:"source_title"`
	SourceDomain string    `json:"source_domain"`
	TargetID     uuid.UUID `json:"target_id"`
	TargetTitle  string    `json:"target_title"`
	TargetDomain string    `json:"target_domain"`
}

// ItemVariations returns the problem relationship graph for learning items.
func (s *Store) ItemVariations(ctx context.Context, domain *string, limit int32) ([]ItemRelation, error) {
	rows, err := s.q.ItemVariations(ctx, db.ItemVariationsParams{
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying item variations: %w", err)
	}
	result := make([]ItemRelation, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ItemRelation{
			RelationID:   r.RelationID,
			RelationType: r.RelationType,
			SourceID:     r.SourceID,
			SourceTitle:  r.SourceTitle,
			SourceDomain: r.SourceDomain,
			TargetID:     r.TargetID,
			TargetTitle:  r.TargetTitle,
			TargetDomain: r.TargetDomain,
		}
	}
	return result, nil
}

func rowToSession(r *db.Session) *Session {
	return &Session{
		ID:              r.ID,
		Domain:          r.Domain,
		Mode:            Mode(r.SessionMode),
		JournalID:       r.JournalID,
		DailyPlanItemID: r.DailyPlanItemID,
		StartedAt:       r.StartedAt,
		EndedAt:         r.EndedAt,
		CreatedAt:       r.CreatedAt,
	}
}

// --- FSRS review card operations ---

// ReviewItem performs a spaced repetition review on a learning item's card,
// deriving the FSRS rating from the attempt outcome via ratingFromOutcome.
// If no card exists, one is created lazily (with unique violation retry for TOCTOU safety).
// The card update + review log insert are atomic via the store's underlying DBTX.
// Callers using a pool get auto-commit per statement; callers using a tx get full atomicity.
func (s *Store) ReviewItem(ctx context.Context, itemID uuid.UUID, outcome string, now time.Time) (time.Time, error) {
	return s.reviewItemWithRating(ctx, itemID, ratingFromOutcome(outcome), now)
}

// ReviewItemWithRating performs a spaced repetition review using an explicit
// FSRS rating (1=Again, 2=Hard, 3=Good, 4=Easy) instead of deriving it from an
// attempt outcome. Use this when recall difficulty is independent of outcome —
// e.g. the attempt was solved_independent but recall was painful (rating=2),
// or needed_help but core concept is solid (rating=3).
//
// Validation errors are wrapped so callers can distinguish an invalid rating
// (user/input error) from a DB failure (infrastructure error).
func (s *Store) ReviewItemWithRating(ctx context.Context, itemID uuid.UUID, rating int, now time.Time) (time.Time, error) {
	fr, err := fsrsRatingFromInt(rating)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid fsrs rating: %w", err)
	}
	return s.reviewItemWithRating(ctx, itemID, fr, now)
}

// reviewItemWithRating is the shared implementation behind ReviewItem and
// ReviewItemWithRating. It takes a resolved gofsrs.Rating so both code paths
// converge without re-doing card lookup or state marshaling.
func (s *Store) reviewItemWithRating(ctx context.Context, itemID uuid.UUID, rating gofsrs.Rating, now time.Time) (time.Time, error) {
	row, err := s.q.CardByLearningItem(ctx, &itemID)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.createAndReviewCard(ctx, itemID, rating, now)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("querying card for item %s: %w", itemID, err)
	}

	cardState, err := unmarshalCardState(row.CardState)
	if err != nil {
		return time.Time{}, fmt.Errorf("unmarshaling card state for card %d: %w", row.ID, err)
	}

	updated, rl := s.sched.review(&cardState, rating, now)
	state, err := marshalCardState(&updated)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshaling card state: %w", err)
	}

	if _, err := s.q.UpdateCardState(ctx, db.UpdateCardStateParams{
		CardState: state,
		Due:       updated.Due,
		ID:        row.ID,
	}); err != nil {
		return time.Time{}, fmt.Errorf("updating review card %d: %w", row.ID, err)
	}

	if err := s.writeReviewLog(ctx, row.ID, rl, now); err != nil {
		return time.Time{}, err
	}

	return updated.Due, nil
}

// createAndReviewCard creates a new FSRS card and immediately reviews it.
// Handles TOCTOU race: if another goroutine created the card concurrently,
// catches the unique violation and falls back to reviewing the existing card.
func (s *Store) createAndReviewCard(ctx context.Context, itemID uuid.UUID, rating gofsrs.Rating, now time.Time) (time.Time, error) {
	newCard := s.sched.newCard()
	updated, rl := s.sched.review(&newCard, rating, now)

	state, err := marshalCardState(&updated)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshaling card state: %w", err)
	}

	row, err := s.q.CreateCardForItem(ctx, db.CreateCardForItemParams{
		LearningItemID: &itemID,
		CardState:      state,
		Due:            updated.Due,
	})
	if err != nil {
		// TOCTOU: another goroutine created the card first. Retry via the review
		// path preserving the caller's original rating — previously this called
		// ReviewItem with "" which silently demoted every rating to Again.
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return s.reviewItemWithRating(ctx, itemID, rating, now)
		}
		return time.Time{}, fmt.Errorf("creating review card for item %s: %w", itemID, err)
	}

	if err := s.writeReviewLog(ctx, row.ID, rl, now); err != nil {
		return time.Time{}, err
	}

	return updated.Due, nil
}

// writeReviewLog appends a review log entry for an FSRS card review.
func (s *Store) writeReviewLog(ctx context.Context, cardID int64, rl gofsrs.ReviewLog, now time.Time) error {
	return s.q.InsertReviewLog(ctx, db.InsertReviewLogParams{
		CardID:        cardID,
		Rating:        int32(rl.Rating),
		ScheduledDays: int32(rl.ScheduledDays), //nolint:gosec // G115: FSRS ScheduledDays is small (days), never exceeds int32
		ElapsedDays:   int32(rl.ElapsedDays),   //nolint:gosec // G115: FSRS ElapsedDays is small (days), never exceeds int32
		State:         int32(rl.State),
		ReviewedAt:    now,
	})
}

// DueReviewCount returns the number of review cards due before the given time.
func (s *Store) DueReviewCount(ctx context.Context, before time.Time) (int, error) {
	n, err := s.q.DueReviewCount(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("counting due reviews: %w", err)
	}
	return int(n), nil
}

// Concept represents a learning concept for API responses.
type Concept struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`
	Kind        string    `json:"kind"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// ConceptObservation is an observation record for concept drilldown.
type ConceptObservation struct {
	ID          uuid.UUID `json:"id"`
	SignalType  string    `json:"signal_type"`
	Category    string    `json:"category"`
	Severity    *string   `json:"severity,omitempty"`
	Detail      *string   `json:"detail,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Outcome     string    `json:"outcome"`
	AttemptedAt time.Time `json:"attempted_at"`
	ItemTitle   string    `json:"item_title"`
}

// ConceptAttempt is an attempt record for concept drilldown.
type ConceptAttempt struct {
	ID              uuid.UUID `json:"id"`
	ItemID          uuid.UUID `json:"item_id"`
	Outcome         string    `json:"outcome"`
	AttemptedAt     time.Time `json:"attempted_at"`
	DurationMinutes *int32    `json:"duration_minutes,omitempty"`
	ItemTitle       string    `json:"item_title"`
	Difficulty      *string   `json:"difficulty,omitempty"`
}

// ConceptItem is an item linked to a concept.
type ConceptItem struct {
	ID         uuid.UUID `json:"id"`
	Title      string    `json:"title"`
	Domain     string    `json:"domain"`
	Difficulty *string   `json:"difficulty,omitempty"`
	ExternalID *string   `json:"external_id,omitempty"`
	Relevance  string    `json:"relevance"`
}

// ConceptBySlug returns a concept by domain and slug.
func (s *Store) ConceptBySlug(ctx context.Context, domain, slug string) (*Concept, error) {
	row, err := s.q.ConceptByDomainSlug(ctx, db.ConceptByDomainSlugParams{
		Domain: domain,
		Slug:   slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying concept %s/%s: %w", domain, slug, err)
	}
	return &Concept{
		ID: row.ID, Slug: row.Slug, Name: row.Name,
		Domain: row.Domain, Kind: row.Kind, Description: row.Description,
		CreatedAt: row.CreatedAt,
	}, nil
}

// ObservationsByConcept returns observations for a concept, newest first.
func (s *Store) ObservationsByConcept(ctx context.Context, conceptID uuid.UUID, limit int32) ([]ConceptObservation, error) {
	rows, err := s.q.ObservationsByConcept(ctx, db.ObservationsByConceptParams{
		ConceptID:  conceptID,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying observations for concept: %w", err)
	}
	result := make([]ConceptObservation, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptObservation{
			ID: r.ID, SignalType: r.SignalType, Category: r.Category,
			Severity: r.Severity, Detail: r.Detail, CreatedAt: r.CreatedAt,
			Outcome: r.Outcome, AttemptedAt: r.AttemptedAt, ItemTitle: r.ItemTitle,
		}
	}
	return result, nil
}

// AttemptsByConcept returns recent attempts on items exercising a concept.
func (s *Store) AttemptsByConcept(ctx context.Context, conceptID uuid.UUID, limit int32) ([]ConceptAttempt, error) {
	rows, err := s.q.AttemptsByConcept(ctx, db.AttemptsByConceptParams{
		ConceptID:  conceptID,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying attempts for concept: %w", err)
	}
	result := make([]ConceptAttempt, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptAttempt{
			ID: r.ID, ItemID: r.LearningItemID, Outcome: r.Outcome,
			AttemptedAt: r.AttemptedAt, DurationMinutes: r.DurationMinutes,
			ItemTitle: r.ItemTitle, Difficulty: r.Difficulty,
		}
	}
	return result, nil
}

// ItemsByConcept returns items linked to a concept.
func (s *Store) ItemsByConcept(ctx context.Context, conceptID uuid.UUID) ([]ConceptItem, error) {
	rows, err := s.q.ItemsByConcept(ctx, conceptID)
	if err != nil {
		return nil, fmt.Errorf("querying items for concept: %w", err)
	}
	result := make([]ConceptItem, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptItem{
			ID: r.ID, Title: r.Title, Domain: r.Domain,
			Difficulty: r.Difficulty, ExternalID: r.ExternalID,
			Relevance: r.Relevance,
		}
	}
	return result, nil
}

// Streak returns the number of consecutive days with at least one completed session.
func (s *Store) Streak(ctx context.Context) (int, error) {
	n, err := s.q.SessionStreak(ctx)
	if err != nil {
		return 0, fmt.Errorf("computing session streak: %w", err)
	}
	return int(n), nil
}
