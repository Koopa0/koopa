package learning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

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
	TargetTitle string    `json:"target_title"`
}

// ConceptTarget is a learning target linked to a concept.
type ConceptTarget struct {
	ID         uuid.UUID `json:"id"`
	Title      string    `json:"title"`
	Domain     string    `json:"domain"`
	Difficulty *string   `json:"difficulty,omitempty"`
	ExternalID *string   `json:"external_id,omitempty"`
	Relevance  string    `json:"relevance"`
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

// FindOrCreateConcept upserts a concept by domain + slug.
func (s *Store) FindOrCreateConcept(ctx context.Context, slug, name, domain, kind string) (uuid.UUID, error) {
	row, err := s.q.FindOrCreateConcept(ctx, db.FindOrCreateConceptParams{
		Slug:   slug,
		Name:   name,
		Domain: domain,
		Kind:   db.ConceptKind(kind),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("finding/creating concept: %w", err)
	}
	return row.ID, nil
}

// ConceptIDsBySlug resolves a batch of concept slugs to their UUIDs. Returns
// a map keyed by slug; slugs that don't match any concept are absent from
// the map. Callers compare len(result) to len(input) to detect missing
// slugs. Used by manage_content to wire content_concepts atomically without
// forcing the caller to know concept UUIDs.
func (s *Store) ConceptIDsBySlug(ctx context.Context, slugs []string) (map[string]uuid.UUID, error) {
	if len(slugs) == 0 {
		return map[string]uuid.UUID{}, nil
	}
	rows, err := s.q.ConceptsBySlug(ctx, slugs)
	if err != nil {
		return nil, fmt.Errorf("resolving concept slugs: %w", err)
	}
	out := make(map[string]uuid.UUID, len(rows))
	for _, r := range rows {
		out[r.Slug] = r.ID
	}
	return out, nil
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
		Domain: row.Domain, Kind: string(row.Kind), Description: row.Description,
		CreatedAt: row.CreatedAt,
	}, nil
}

// ConceptMastery returns per-concept mastery with signal counts and
// first/last observation timestamps. Rows contain only concepts with at
// least one observation in the window — unexplored concepts are not
// returned. Presentation-layer formatting (e.g. mastery stage derivation)
// belongs to the caller, not this store.
//
// confidenceFilter: "high" (default) or "all". Empty string is treated as
// "high" so callers don't have to remember the default; any other value
// is rejected with ErrInvalidInput so a typo can't silently degrade to
// "high" via the SQL predicate. The mastery stage floor in the caller
// MUST look at the FILTERED counts returned here, not at total
// observations — that property is the difference between "confidence is
// a label" and "confidence is a half-gate".
func (s *Store) ConceptMastery(ctx context.Context, domain *string, since time.Time, confidenceFilter string) ([]ConceptMasteryRow, error) {
	confidenceFilter, err := normalizeConfidenceFilter(confidenceFilter)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ConceptMastery(ctx, db.ConceptMasteryParams{
		Domain:           domain,
		Since:            since,
		ConfidenceFilter: confidenceFilter,
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
			Kind:              string(r.Kind),
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

// WeaknessAnalysis returns cross-pattern weakness analysis. Same
// confidenceFilter semantics as ConceptMastery — "high" (default) or "all".
// Invalid values are rejected with ErrInvalidInput.
func (s *Store) WeaknessAnalysis(ctx context.Context, domain *string, since time.Time, confidenceFilter string) ([]WeaknessRow, error) {
	confidenceFilter, err := normalizeConfidenceFilter(confidenceFilter)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.WeaknessAnalysis(ctx, db.WeaknessAnalysisParams{
		Domain:           domain,
		Since:            since,
		ConfidenceFilter: confidenceFilter,
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
			Outcome: r.Outcome, AttemptedAt: r.AttemptedAt, TargetTitle: r.TargetTitle,
		}
	}
	return result, nil
}

// AttemptsByConcept returns recent attempts that produced an observation
// about the given concept, newest first. Each Attempt carries a
// MatchedObservationID pointer — the id of the highest-priority
// observation on that attempt that linked it to this concept. Callers
// wanting the full observations list on each attempt should invoke
// AttachObservations afterward; this method intentionally does not
// bundle the two fetches so the cost of the observation batch is
// explicit at the call site.
func (s *Store) AttemptsByConcept(ctx context.Context, conceptID uuid.UUID, limit int32) ([]Attempt, error) {
	rows, err := s.q.AttemptsByConcept(ctx, db.AttemptsByConceptParams{
		ConceptID:  conceptID,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying attempts for concept %s: %w", conceptID, err)
	}
	result := make([]Attempt, len(rows))
	for i := range rows {
		r := &rows[i]
		matchID := r.MatchedObservationID
		result[i] = Attempt{
			ID:                   r.ID,
			LearningTargetID:     r.LearningTargetID,
			SessionID:            r.SessionID,
			AttemptNumber:        r.AttemptNumber,
			Paradigm:             Paradigm(r.Paradigm),
			Outcome:              r.Outcome,
			DurationMinutes:      r.DurationMinutes,
			StuckAt:              r.StuckAt,
			ApproachUsed:         r.ApproachUsed,
			AttemptedAt:          r.AttemptedAt,
			Metadata:             r.Metadata,
			TargetTitle:          r.TargetTitle,
			TargetExternalID:     r.TargetExternalID,
			Difficulty:           r.Difficulty,
			MatchedObservationID: &matchID,
		}
	}
	return result, nil
}

// TargetsByConcept returns learning targets linked to a concept.
func (s *Store) TargetsByConcept(ctx context.Context, conceptID uuid.UUID) ([]ConceptTarget, error) {
	rows, err := s.q.LearningTargetsByConcept(ctx, conceptID)
	if err != nil {
		return nil, fmt.Errorf("querying targets for concept: %w", err)
	}
	result := make([]ConceptTarget, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptTarget{
			ID: r.ID, Title: r.Title, Domain: r.Domain,
			Difficulty: r.Difficulty, ExternalID: r.ExternalID,
			Relevance: r.Relevance,
		}
	}
	return result, nil
}
