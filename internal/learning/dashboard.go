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

// WeekActivityDay is one day inside DashboardResponse.WeekActivity.
type WeekActivityDay struct {
	// Date is the UTC day in YYYY-MM-DD form.
	Date string `json:"date"`
	// Attempts counts learning_attempts created on that day.
	Attempts int `json:"attempts"`
}

// WeekActivity returns the last seven UTC days of attempt-logging
// activity (learning_attempts.created_at), zero-filled for empty days,
// oldest first — the day containing now is always the last element.
func (s *Store) WeekActivity(ctx context.Context, now time.Time) ([]WeekActivityDay, error) {
	y, m, d := now.UTC().Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	since := today.AddDate(0, 0, -6)

	rows, err := s.q.WeekAttemptCounts(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying week attempt counts: %w", err)
	}
	counts := make(map[string]int, len(rows))
	for i := range rows {
		counts[rows[i].Day.Format(time.DateOnly)] = int(rows[i].Attempts)
	}

	out := make([]WeekActivityDay, 7)
	for i := range 7 {
		date := since.AddDate(0, 0, i).Format(time.DateOnly)
		out[i] = WeekActivityDay{Date: date, Attempts: counts[date]}
	}
	return out, nil
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
