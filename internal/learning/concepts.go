// Copyright 2026 Koopa. All rights reserved.

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

// SignalCounts is the (weakness, improvement, mastery) triple surfaced
// in both /concepts list rows and /concepts/{slug} detail responses.
// JSON tags pin the wire shape — DO NOT rename without checking the
// frontend api-spec.md §4.2 / §4.3 contracts.
type SignalCounts struct {
	Weakness    int64 `json:"weakness"`
	Improvement int64 `json:"improvement"`
	Mastery     int64 `json:"mastery"`
}

// ConceptListNextDueTarget is the nested per-row next_due_target object.
// All three fields are required wire fields when the parent is non-null;
// the parent itself is `null` when the concept has no linked review card.
// `due_at` is nullable inside the object to honour the api-spec shape.
type ConceptListNextDueTarget struct {
	ID    uuid.UUID  `json:"id"`
	Title string     `json:"title"`
	DueAt *time.Time `json:"due_at"`
}

// ConceptListRow is one item in the /api/admin/learning/concepts
// response array.
type ConceptListRow struct {
	Slug          string                    `json:"slug"`
	Kind          string                    `json:"kind"`
	Domain        string                    `json:"domain"`
	MasteryStage  MasteryStage              `json:"mastery_stage"`
	MasteryCounts SignalCounts              `json:"mastery_counts"`
	ObsCount      int64                     `json:"obs_count"`
	ParentSlug    *string                   `json:"parent_slug"`
	NextDueTarget *ConceptListNextDueTarget `json:"next_due_target"`
}

// NamedConcept is the {slug, name} pair used for parent + children on
// concept detail responses.
type NamedConcept struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// ConceptDetailLinkedNote / ConceptDetailLinkedContent / ConceptDetailRelation
// are stub types — the spec defines their shapes for future work but
// this PR returns empty arrays for all three. They exist so future
// implementations can swap in real data without re-shaping the response.
type ConceptDetailLinkedNote struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Kind     string    `json:"kind"`
	Maturity string    `json:"maturity"`
}

type ConceptDetailLinkedContent struct {
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
	Type  string    `json:"type"`
}

type ConceptDetailRelation struct {
	Type    string       `json:"type"`
	Concept NamedConcept `json:"concept"`
}

// ConceptDetailRecentAttempt is the slim attempt projection on concept
// detail — strictly id/target_title/outcome/created_at. The full
// Attempt struct (metadata, external_id, etc.) is deliberately not
// inlined; recent_attempts on the wire stays narrow so a follow-up
// "attempt detail" view can shape its own response without competing
// with this endpoint.
type ConceptDetailRecentAttempt struct {
	ID          uuid.UUID `json:"id"`
	TargetTitle string    `json:"target_title"`
	Outcome     string    `json:"outcome"`
	CreatedAt   time.Time `json:"created_at"`
}

// ConceptDetailResponse is the wire shape for
// GET /api/admin/learning/concepts/{slug}?domain=...
type ConceptDetailResponse struct {
	Slug                string                       `json:"slug"`
	Kind                string                       `json:"kind"`
	Domain              string                       `json:"domain"`
	Name                string                       `json:"name"`
	Description         string                       `json:"description"`
	MasteryStage        MasteryStage                 `json:"mastery_stage"`
	MasteryCounts       SignalCounts                 `json:"mastery_counts"`
	LowConfidenceCounts SignalCounts                 `json:"low_confidence_counts"`
	Parent              *NamedConcept                `json:"parent"`
	Children            []NamedConcept               `json:"children"`
	Relations           []ConceptDetailRelation      `json:"relations"`
	LinkedNotes         []ConceptDetailLinkedNote    `json:"linked_notes"`
	LinkedContents      []ConceptDetailLinkedContent `json:"linked_contents"`
	RecentAttempts      []ConceptDetailRecentAttempt `json:"recent_attempts"`
	RecentObservations  []DashboardRecentObservation `json:"recent_observations"`
}

// ConceptListFilter bundles the optional query parameters accepted by
// the /concepts list endpoint. Empty string / empty slice means "no
// filter for that axis".
type ConceptListFilter struct {
	Domain           string
	Kind             string
	Q                string
	ConfidenceFilter string
	MasteryStages    []string
}

// ConceptsList returns one row per non-archived concept matching the
// filter, with mastery aggregations computed under the requested
// confidence_filter. The MasteryStages slice is applied in Go (post
// DeriveMasteryStage) because the stage decision uses the
// MinObservationsForVerdict floor — pushing the filter into SQL would
// require duplicating that decision rule, which is the canonical
// reason to keep it Go-side.
func (s *Store) ConceptsList(ctx context.Context, f ConceptListFilter, since time.Time) ([]ConceptListRow, error) {
	confidenceFilter, err := normalizeConfidenceFilter(f.ConfidenceFilter)
	if err != nil {
		return nil, err
	}
	params := db.ConceptsForListParams{
		Since:            since,
		ConfidenceFilter: confidenceFilter,
	}
	if f.Domain != "" {
		params.Domain = &f.Domain
	}
	if f.Kind != "" {
		params.Kind = &f.Kind
	}
	if f.Q != "" {
		params.Q = &f.Q
	}

	rows, err := s.q.ConceptsForList(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("querying concepts list: %w", err)
	}

	stageFilter := normaliseStageFilter(f.MasteryStages)

	result := make([]ConceptListRow, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		stage := DeriveMasteryStage(r.WeaknessCount, r.ImprovementCount, r.MasteryCount)
		if !stageFilter.matches(stage) {
			continue
		}
		row := ConceptListRow{
			Slug:         r.Slug,
			Kind:         string(r.Kind),
			Domain:       r.Domain,
			MasteryStage: stage,
			MasteryCounts: SignalCounts{
				Weakness:    r.WeaknessCount,
				Improvement: r.ImprovementCount,
				Mastery:     r.MasteryCount,
			},
			ObsCount:   r.TotalObservations,
			ParentSlug: r.ParentSlug,
		}
		if r.NextDueTargetID != nil && r.NextDueTargetTitle != nil {
			row.NextDueTarget = &ConceptListNextDueTarget{
				ID:    *r.NextDueTargetID,
				Title: *r.NextDueTargetTitle,
				DueAt: r.NextDueAt,
			}
		}
		result = append(result, row)
	}
	return result, nil
}

// stageMatcher implements the post-derivation mastery_stage filter.
// Empty matcher (no filter requested) matches every stage so callers
// receive all rows.
type stageMatcher struct {
	all bool
	set map[MasteryStage]struct{}
}

func normaliseStageFilter(stages []string) stageMatcher {
	if len(stages) == 0 {
		return stageMatcher{all: true}
	}
	m := stageMatcher{set: make(map[MasteryStage]struct{}, len(stages))}
	for _, s := range stages {
		switch s {
		case "struggling", "developing", "solid":
			m.set[MasteryStage(s)] = struct{}{}
		}
	}
	if len(m.set) == 0 {
		// Every value was unknown — treat as "no filter" rather than
		// silently returning zero rows. The handler already rejects
		// unknown stages at the boundary.
		m.all = true
	}
	return m
}

func (m stageMatcher) matches(s MasteryStage) bool {
	if m.all {
		return true
	}
	_, ok := m.set[s]
	return ok
}

// ConceptDetail loads the full /concepts/{slug} detail payload.
// Returns ErrNotFound if no live concept matches (domain, slug). The
// caller is expected to have validated that domain is non-empty.
func (s *Store) ConceptDetail(ctx context.Context, domain, slug, confidenceFilter string, recentLimit int32) (*ConceptDetailResponse, error) {
	confidenceFilter, err := normalizeConfidenceFilter(confidenceFilter)
	if err != nil {
		return nil, err
	}

	concept, err := s.q.ConceptByDomainSlug(ctx, db.ConceptByDomainSlugParams{
		Domain: domain,
		Slug:   slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying concept %s/%s: %w", domain, slug, err)
	}

	counts, err := s.q.ConceptMasteryCountsForConcept(ctx, db.ConceptMasteryCountsForConceptParams{
		ConfidenceFilter: confidenceFilter,
		ConceptID:        concept.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("querying concept mastery counts: %w", err)
	}

	parentChildren, err := s.q.ConceptParentChildren(ctx, concept.ID)
	if err != nil {
		return nil, fmt.Errorf("querying concept parent/children: %w", err)
	}

	attempts, err := s.q.RecentAttemptsByConceptSlim(ctx, db.RecentAttemptsByConceptSlimParams{
		ConceptID:  concept.ID,
		MaxResults: recentLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent attempts: %w", err)
	}

	obsRows, err := s.q.RecentObservationsByConcept(ctx, db.RecentObservationsByConceptParams{
		ConceptID:  concept.ID,
		MaxResults: recentLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent observations: %w", err)
	}

	resp := &ConceptDetailResponse{
		Slug:        concept.Slug,
		Kind:        string(concept.Kind),
		Domain:      concept.Domain,
		Name:        concept.Name,
		Description: concept.Description,
		MasteryStage: DeriveMasteryStage(
			counts.WeaknessCount, counts.ImprovementCount, counts.MasteryCount,
		),
		MasteryCounts: SignalCounts{
			Weakness:    counts.WeaknessCount,
			Improvement: counts.ImprovementCount,
			Mastery:     counts.MasteryCount,
		},
		LowConfidenceCounts: SignalCounts{
			Weakness:    counts.LowWeaknessCount,
			Improvement: counts.LowImprovementCount,
			Mastery:     counts.LowMasteryCount,
		},
		Children:           []NamedConcept{},
		Relations:          []ConceptDetailRelation{},
		LinkedNotes:        []ConceptDetailLinkedNote{},
		LinkedContents:     []ConceptDetailLinkedContent{},
		RecentAttempts:     make([]ConceptDetailRecentAttempt, len(attempts)),
		RecentObservations: make([]DashboardRecentObservation, len(obsRows)),
	}

	for i := range parentChildren {
		nc := NamedConcept{Slug: parentChildren[i].Slug, Name: parentChildren[i].Name}
		switch parentChildren[i].Role {
		case "parent":
			resp.Parent = &nc
		case "child":
			resp.Children = append(resp.Children, nc)
		}
	}

	for i := range attempts {
		a := &attempts[i]
		resp.RecentAttempts[i] = ConceptDetailRecentAttempt{
			ID:          a.ID,
			TargetTitle: a.TargetTitle,
			Outcome:     a.Outcome,
			CreatedAt:   a.AttemptedAt,
		}
	}

	for i := range obsRows {
		o := &obsRows[i]
		resp.RecentObservations[i] = DashboardRecentObservation{
			ID:          o.ID,
			Signal:      o.SignalType,
			Category:    o.Category,
			Body:        o.Body,
			Domain:      o.Domain,
			ConceptSlug: o.ConceptSlug,
			Confidence:  o.Confidence,
			CreatedAt:   o.CreatedAt,
		}
	}

	return resp, nil
}
