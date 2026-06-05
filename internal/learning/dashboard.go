// Copyright 2026 Koopa. All rights reserved.

package learning

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// DashboardConceptRow is one row inside DashboardResponse.Concepts.Rows.
// MasteryValue is the raw ratio (no floor); MasteryStage is the floored
// verdict from DeriveMasteryStage. See mastery.go for why these diverge.
type DashboardConceptRow struct {
	Slug         string       `json:"slug"`
	Kind         string       `json:"kind"`
	Domain       string       `json:"domain"`
	ObsCount     int64        `json:"obs_count"`
	MasteryValue float64      `json:"mastery_value"`
	MasteryStage MasteryStage `json:"mastery_stage"`
}

// DashboardConcepts is the concepts envelope on the dashboard response.
// CountTotal equals len(Rows); CountsByDomain is computed from the same
// row set (filtered by domain + confidence_filter) so a domain-scoped
// request yields a single-entry map.
type DashboardConcepts struct {
	CountTotal     int                   `json:"count_total"`
	CountsByDomain map[string]int        `json:"counts_by_domain"`
	Rows           []DashboardConceptRow `json:"rows"`
}

// DashboardDueTodayTarget is the nested target ref inside a due-today item.
type DashboardDueTodayTarget struct {
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
}

// DashboardDueTodayItem is one row inside DashboardResponse.DueToday.Items.
// Retention is computed at request time from the FSRS card_state JSONB —
// see fsrs.Store.Retention. LastReviewedAt is NULL for cards inserted
// without a review log (a record_attempt path may stamp a card but not
// log a review).
type DashboardDueTodayItem struct {
	CardID         uuid.UUID               `json:"card_id"`
	Target         DashboardDueTodayTarget `json:"target"`
	Domain         string                  `json:"domain"`
	Retention      float64                 `json:"retention"`
	LastReviewedAt *time.Time              `json:"last_reviewed_at"`
}

// DashboardDueToday is the due_today envelope. Count == len(Items).
type DashboardDueToday struct {
	Count int                     `json:"count"`
	Items []DashboardDueTodayItem `json:"items"`
}

// DashboardRecentObservation is one row inside DashboardResponse.RecentObservations.
// Wire field renames vs. the schema columns:
//
//	signal_type → signal
//	detail      → body (and NULL → "" — body is non-nullable on the wire)
type DashboardRecentObservation struct {
	ID          uuid.UUID `json:"id"`
	Signal      string    `json:"signal"`
	Category    string    `json:"category"`
	Body        string    `json:"body"`
	Domain      string    `json:"domain"`
	ConceptSlug string    `json:"concept_slug"`
	Confidence  string    `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
}

// DashboardConceptRows returns observation-backed concept rows for the
// dashboard. confidenceFilter follows ConceptMastery semantics: "high"
// (default) or "all"; invalid values return ErrInvalidInput.
func (s *Store) DashboardConceptRows(ctx context.Context, domain *string, since time.Time, confidenceFilter string) ([]DashboardConceptRow, error) {
	confidenceFilter, err := normalizeConfidenceFilter(confidenceFilter)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.DashboardConceptRows(ctx, db.DashboardConceptRowsParams{
		Domain:           domain,
		Since:            since,
		ConfidenceFilter: confidenceFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("querying dashboard concept rows: %w", err)
	}
	result := make([]DashboardConceptRow, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = DashboardConceptRow{
			Slug:         r.Slug,
			Kind:         string(r.Kind),
			Domain:       r.Domain,
			ObsCount:     r.TotalObservations,
			MasteryValue: MasteryValue(r.MasteryCount, r.TotalObservations),
			MasteryStage: DeriveMasteryStage(r.WeaknessCount, r.ImprovementCount, r.MasteryCount),
		}
	}
	return result, nil
}

// RetentionFn computes a card's FSRS retrievability from its card_state
// JSONB at the given moment. Implemented by *fsrs.Store; passed in here
// so dashboard.go doesn't import internal/learning/fsrs.
type RetentionFn = func(state []byte, now time.Time) float64

// DashboardDueReviews returns the due-card items for the dashboard,
// already wrapped in the response DTO shape. retention is computed
// per-row from card_state via the supplied RetentionFn. now is the
// reference instant for retention computation (typically time.Now() at
// the handler boundary).
func (s *Store) DashboardDueReviews(ctx context.Context, domain *string, dueBefore time.Time, limit int32, retention RetentionFn, now time.Time) ([]DashboardDueTodayItem, error) {
	rows, err := s.q.DashboardDueReviews(ctx, db.DashboardDueReviewsParams{
		DueBefore:  dueBefore,
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying dashboard due reviews: %w", err)
	}
	result := make([]DashboardDueTodayItem, len(rows))
	for i := range rows {
		r := &rows[i]
		var ret float64
		if retention != nil {
			ret = retention(r.CardState, now)
		}
		result[i] = DashboardDueTodayItem{
			CardID: r.CardID,
			Target: DashboardDueTodayTarget{
				ID:    r.TargetID,
				Title: r.TargetTitle,
			},
			Domain:         r.Domain,
			Retention:      ret,
			LastReviewedAt: r.LastReviewedAt,
		}
	}
	return result, nil
}

// DashboardRecentObservations returns the recent_observations slice for
// the dashboard. Field renames (signal_type → signal, detail → body)
// happen here; the SQL preserves schema-native names.
func (s *Store) DashboardRecentObservations(ctx context.Context, domain *string, confidenceFilter string, limit int32) ([]DashboardRecentObservation, error) {
	confidenceFilter, err := normalizeConfidenceFilter(confidenceFilter)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.DashboardRecentObservations(ctx, db.DashboardRecentObservationsParams{
		Domain:           domain,
		ConfidenceFilter: confidenceFilter,
		MaxResults:       limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying dashboard recent observations: %w", err)
	}
	result := make([]DashboardRecentObservation, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = DashboardRecentObservation{
			ID:          r.ID,
			Signal:      r.SignalType,
			Category:    r.Category,
			Body:        r.Body,
			Domain:      r.Domain,
			ConceptSlug: r.ConceptSlug,
			Confidence:  r.Confidence,
			CreatedAt:   r.CreatedAt,
		}
	}
	return result, nil
}
