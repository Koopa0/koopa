package learning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// RelationType is a learning target relationship kind — must match the
// learning_target_relations.relation_type CHECK constraint in migration 001.
type RelationType string

// learning_target_relations.relation_type allowed values.
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

// RetrievalTarget represents a learning target due for spaced review.
//
// DriftSuspect is true when the card's most recent attempt-driven review
// could not be applied cleanly (see fsrs.MarkDrift). A consumer seeing this
// flag should treat the due date as possibly stale — the recommended UX is
// to re-review manually rather than trusting the schedule. DriftReason
// labels the cause for debugging.
type RetrievalTarget struct {
	CardID       uuid.UUID `json:"card_id"`
	Due          time.Time `json:"due"`
	TargetID     uuid.UUID `json:"target_id"`
	Title        string    `json:"title"`
	Domain       string    `json:"domain"`
	Difficulty   *string   `json:"difficulty,omitempty"`
	ExternalID   *string   `json:"external_id,omitempty"`
	DriftSuspect bool      `json:"drift_suspect"`
	DriftReason  *string   `json:"drift_reason,omitempty"`
}

// TargetRelation represents a relationship between two learning targets,
// with per-related-target attempt stats so the dashboard variations view can
// drive decisions ("has Koopa tried this variant, and how did it go?")
// without an N+1 lookup.
//
// Direction: (anchor, related, relation_type) means "related is a
// <relation_type> of anchor" — see schema comment on
// learning_target_relations for the rationale behind anchor/related vs
// source/target naming.
//
// RelatedAttemptCount is 0 when the related target has never been attempted.
// RelatedLastOutcome and RelatedLastAttemptedAt are nil in that case —
// explicitly distinguishing "no attempts" from any possible sentinel value.
type TargetRelation struct {
	RelationID             uuid.UUID  `json:"relation_id"`
	RelationType           string     `json:"relation_type"`
	AnchorID               uuid.UUID  `json:"anchor_id"`
	AnchorTitle            string     `json:"anchor_title"`
	AnchorDomain           string     `json:"anchor_domain"`
	RelatedID              uuid.UUID  `json:"related_id"`
	RelatedTitle           string     `json:"related_title"`
	RelatedDomain          string     `json:"related_domain"`
	RelatedAttemptCount    int64      `json:"related_attempt_count"`
	RelatedLastOutcome     *string    `json:"related_last_outcome,omitempty"`
	RelatedLastAttemptedAt *time.Time `json:"related_last_attempted_at,omitempty"`
}

// TargetNote is a lightweight note projection returned by target-writeup queries.
// Distinct from note.Note so the learning package doesn't force a cross-package
// conversion on consumers that only want the common fields.
type TargetNote struct {
	ID        uuid.UUID
	Slug      string
	Title     string
	Body      string
	Kind      string
	Maturity  string
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TargetContent is a lightweight content projection for target-writeup listings.
type TargetContent struct {
	ID          uuid.UUID
	Slug        string
	Title       string
	Type        string
	Status      string
	IsPublic    bool
	PublishedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// FindTarget looks up a learning target by (domain, title) without creating
// it. Returns ErrNotFound if the target does not exist. Used by read-only
// tools like attempt_history that must not silently pollute the catalog.
func (s *Store) FindTarget(ctx context.Context, domain, title string) (uuid.UUID, error) {
	row, err := s.q.FindTargetByDomainTitle(ctx, db.FindTargetByDomainTitleParams{
		Domain: domain,
		Title:  title,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("looking up target %s/%s: %w", domain, title, err)
	}
	return row.ID, nil
}

// FindOrCreateTarget upserts a learning target by (domain, external_id) when
// external_id is supplied, or by (domain, title) exact match when it is not.
//
// The title-only path exists because multiple call sites legitimately resolve
// a target without knowing its external provider ID — e.g. manage_plan.
// add_entries accepts a plain title. Without this branch, a plan-added entry
// for "House Robber" and a record_attempt for the same problem (with
// external_id="leetcode-198") would live as two separate learning_targets
// rows, silently splitting the attempt history and mastery signals. The
// title match is case-sensitive on purpose: case differences ("Two Sum"
// vs "two sum") are preserved so intentionally distinct titles are not
// force-merged.
//
// Concurrency: the partial unique index uq_learning_targets_domain_title_no_external
// (migration 001) covers the title-only path. Two concurrent title-only
// callers that both miss the SELECT-first lookup will race to INSERT; the
// loser's INSERT fails with 23505, and the retry below re-reads and
// returns the winner's row. No duplicate survives the race.
func (s *Store) FindOrCreateTarget(ctx context.Context, domain, title string, externalID, difficulty *string) (uuid.UUID, error) {
	titleOnly := externalID == nil || *externalID == ""
	if titleOnly {
		if id, err := s.FindTarget(ctx, domain, title); err == nil {
			return id, nil
		} else if !errors.Is(err, ErrNotFound) {
			return uuid.Nil, err
		}
	}
	row, err := s.q.FindOrCreateLearningTarget(ctx, db.FindOrCreateLearningTargetParams{
		Domain:     domain,
		Title:      title,
		ExternalID: externalID,
		Difficulty: difficulty,
	})
	if err == nil {
		return row.ID, nil
	}
	if titleOnly {
		if id, ok := s.resolveTitleOnlyRace(ctx, domain, title, err); ok {
			return id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("finding/creating learning target: %w", err)
}

// resolveTitleOnlyRace recovers from a uq_learning_targets_domain_title_no_external
// collision by re-reading the row a concurrent caller just inserted. Only
// acts when insertErr is a 23505 unique_violation; otherwise returns
// false so the caller surfaces the original error. Index lives in
// migration 001.
func (s *Store) resolveTitleOnlyRace(ctx context.Context, domain, title string, insertErr error) (uuid.UUID, bool) {
	pgErr, ok := errors.AsType[*pgconn.PgError](insertErr)
	if !ok || pgErr.Code != pgerrcode.UniqueViolation {
		return uuid.Nil, false
	}
	id, err := s.FindTarget(ctx, domain, title)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// LinkTargets inserts a learning_target_relations row from anchorID to
// relatedID with relation. Enforces the invariants LinkTargets owns:
//   - anchorID != relatedID
//   - relation is in the allowlist
//
// Cross-domain rejection is NOT enforced here. The caller already has the
// anchor domain in scope and resolves the related target via
// FindOrCreateTarget, which bakes the domain into the row — a domain check
// here would be two extra round-trips per attempt for a rule the caller can
// check locally. The caller is expected to pre-validate same-domain before
// calling LinkTargets.
//
// Idempotent: conflicts on (anchor, related, relation) are ignored so the
// same pair can be re-linked from a later session without error.
func (s *Store) LinkTargets(ctx context.Context, anchorID, relatedID uuid.UUID, relation RelationType) error {
	if anchorID == relatedID {
		return fmt.Errorf("%w: cannot link target %s to itself", ErrInvalidInput, anchorID)
	}
	if !ValidRelationType(relation) {
		return fmt.Errorf("%w: unknown relation_type %q", ErrInvalidInput, relation)
	}
	if err := s.q.InsertLearningTargetRelation(ctx, db.InsertLearningTargetRelationParams{
		AnchorID:     anchorID,
		RelatedID:    relatedID,
		RelationType: string(relation),
	}); err != nil {
		return fmt.Errorf("inserting learning target relation: %w", err)
	}
	return nil
}

// TargetVariations returns the problem relationship graph for learning targets.
func (s *Store) TargetVariations(ctx context.Context, domain *string, limit int32) ([]TargetRelation, error) {
	rows, err := s.q.LearningTargetVariations(ctx, db.LearningTargetVariationsParams{
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying target variations: %w", err)
	}
	result := make([]TargetRelation, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = TargetRelation{
			RelationID:             r.RelationID,
			RelationType:           r.RelationType,
			AnchorID:               r.AnchorID,
			AnchorTitle:            r.AnchorTitle,
			AnchorDomain:           r.AnchorDomain,
			RelatedID:              r.RelatedID,
			RelatedTitle:           r.RelatedTitle,
			RelatedDomain:          r.RelatedDomain,
			RelatedAttemptCount:    r.RelatedAttemptCount,
			RelatedLastOutcome:     r.RelatedLastOutcome,
			RelatedLastAttemptedAt: r.RelatedLastAttemptedAt,
		}
	}
	return result, nil
}

// RetrievalQueue returns learning targets due for spaced review.
func (s *Store) RetrievalQueue(ctx context.Context, domain *string, dueBefore time.Time, limit int32) ([]RetrievalTarget, error) {
	rows, err := s.q.RetrievalQueue(ctx, db.RetrievalQueueParams{
		DueBefore:  dueBefore,
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying retrieval queue: %w", err)
	}
	result := make([]RetrievalTarget, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = RetrievalTarget{
			CardID:       r.CardID,
			Due:          r.Due,
			TargetID:     r.TargetID,
			Title:        r.Title,
			Domain:       r.Domain,
			Difficulty:   r.Difficulty,
			ExternalID:   r.ExternalID,
			DriftSuspect: r.DriftSuspect,
			DriftReason:  r.LastDriftReason,
		}
	}
	return result, nil
}

// ============================================================
// Learning target writeup junctions
//
// Two N:M attach paths (notes + contents). Intentionally not polymorphic:
// notes and contents are distinct entities with different lifecycles.
// ============================================================

// AttachNote idempotently attaches a note to a target. A repeat attach is a no-op.
func (s *Store) AttachNote(ctx context.Context, targetID, noteID uuid.UUID) error {
	if err := s.q.AttachNoteToTarget(ctx, db.AttachNoteToTargetParams{
		TargetID: targetID,
		NoteID:   noteID,
	}); err != nil {
		return fmt.Errorf("attaching note %s to target %s: %w", noteID, targetID, err)
	}
	return nil
}

// DetachNote removes the attach row. Returns ErrNotFound when no row matched.
func (s *Store) DetachNote(ctx context.Context, targetID, noteID uuid.UUID) error {
	n, err := s.q.DetachNoteFromTarget(ctx, db.DetachNoteFromTargetParams{
		TargetID: targetID,
		NoteID:   noteID,
	})
	if err != nil {
		return fmt.Errorf("detaching note %s from target %s: %w", noteID, targetID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// NotesForTarget returns all notes attached to a target, newest-updated first.
func (s *Store) NotesForTarget(ctx context.Context, targetID uuid.UUID) ([]TargetNote, error) {
	rows, err := s.q.NotesForTarget(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("listing notes for target %s: %w", targetID, err)
	}
	out := make([]TargetNote, len(rows))
	for i := range rows {
		out[i] = TargetNote{
			ID:        rows[i].ID,
			Slug:      rows[i].Slug,
			Title:     rows[i].Title,
			Body:      rows[i].Body,
			Kind:      string(rows[i].Kind),
			Maturity:  string(rows[i].Maturity),
			CreatedBy: rows[i].CreatedBy,
			CreatedAt: rows[i].CreatedAt,
			UpdatedAt: rows[i].UpdatedAt,
		}
	}
	return out, nil
}

// CanonicalNoteForTarget returns the canonical writeup note for a target,
// resolved via learning_domains.canonical_writeup_kind. Returns
// (nil, nil) — not an error — when the domain has no canonical rule or
// no note of the canonical kind is attached yet. Caller distinguishes
// 'no canonical' from 'lookup error' by nil vs error.
func (s *Store) CanonicalNoteForTarget(ctx context.Context, targetID uuid.UUID) (*TargetNote, error) {
	row, err := s.q.CanonicalNoteForTarget(ctx, targetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying canonical note for target %s: %w", targetID, err)
	}
	return &TargetNote{
		ID:        row.ID,
		Slug:      row.Slug,
		Title:     row.Title,
		Body:      row.Body,
		Kind:      string(row.Kind),
		Maturity:  string(row.Maturity),
		CreatedBy: row.CreatedBy,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

// AttachContent idempotently attaches a content row (article/essay/etc) to a target.
func (s *Store) AttachContent(ctx context.Context, targetID, contentID uuid.UUID) error {
	if err := s.q.AttachContentToTarget(ctx, db.AttachContentToTargetParams{
		TargetID:  targetID,
		ContentID: contentID,
	}); err != nil {
		return fmt.Errorf("attaching content %s to target %s: %w", contentID, targetID, err)
	}
	return nil
}

// DetachContent removes the attach row. Returns ErrNotFound when no row matched.
func (s *Store) DetachContent(ctx context.Context, targetID, contentID uuid.UUID) error {
	n, err := s.q.DetachContentFromTarget(ctx, db.DetachContentFromTargetParams{
		TargetID:  targetID,
		ContentID: contentID,
	})
	if err != nil {
		return fmt.Errorf("detaching content %s from target %s: %w", contentID, targetID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ContentsForTarget returns all contents attached to a target, newest-updated first.
func (s *Store) ContentsForTarget(ctx context.Context, targetID uuid.UUID) ([]TargetContent, error) {
	rows, err := s.q.ContentsForTarget(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("listing contents for target %s: %w", targetID, err)
	}
	out := make([]TargetContent, len(rows))
	for i := range rows {
		out[i] = TargetContent{
			ID:          rows[i].ID,
			Slug:        rows[i].Slug,
			Title:       rows[i].Title,
			Type:        string(rows[i].Type),
			Status:      string(rows[i].Status),
			IsPublic:    rows[i].IsPublic,
			PublishedAt: rows[i].PublishedAt,
			CreatedAt:   rows[i].CreatedAt,
			UpdatedAt:   rows[i].UpdatedAt,
		}
	}
	return out, nil
}
