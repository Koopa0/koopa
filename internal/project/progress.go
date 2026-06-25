// Copyright 2026 Koopa. All rights reserved.

// progress.go holds the project_progress read model: the owner's PARA
// momentum/stalled intelligence, computed LIVE at read time from
// activity_events (the single source of truth for "what happened, by
// whom"). Nothing here is stored — there is no momentum/stalled column
// and no snapshot table. The store methods run the JOIN-and-now() reads;
// the pure decision functions (Stalled, AreaNeglected) hold the rules so
// they can be unit-tested against hand-computed inputs without a database.
//
// HUMAN-ACTIVITY-ONLY is the load-bearing semantic: only activity_events
// rows with actor = 'human' count as owner progress. Agent/system actors
// (hermes, codex, claude, system, …) are excluded in SQL, so a
// project worked only by a cron agent reads as having no human activity —
// which is the point.

package project

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Cadence-to-days mapping for the stalled threshold. expected_cadence is a
// closed set guarded by the projects.expected_cadence CHECK; cadenceDays
// maps each value to its calendar-day period. An unrecognised cadence
// yields 0, which makes Stalled return false (no threshold to exceed) — a
// project_progress row can only carry one of these four values, so a 0 here
// signals a schema/code drift the caller can treat as "not stalled".
var cadenceDays = map[string]int{
	"daily":    1,
	"weekly":   7,
	"biweekly": 14,
	"monthly":  30,
}

// AreaNeglectedThreshold is the calendar-day window after which an area
// with no human activity across ALL its projects is flagged neglected.
// Owner-set; named so it is easy to tune in one place.
const AreaNeglectedThreshold = 14 * 24 * time.Hour

// stalledFactor multiplies the cadence period to set the stalled threshold:
// a project is overdue once it has gone more than 2× its expected cadence
// without human activity. Named so the "2×" rule is not a bare literal.
const stalledFactor = 2

// ProjectMomentum is one candidate project's live momentum signal. It is
// populated entirely from a read-time JOIN — no field is persisted.
// LastHumanActivityAt is nil when no human (actor='human') event is scoped
// to the project; the project still appears (it is a candidate by status +
// cadence), it simply has no human activity yet.
type ProjectMomentum struct {
	Slug                string     `json:"slug"`
	Title               string     `json:"title"`
	GoalID              *uuid.UUID `json:"goal_id,omitempty"`
	GoalTitle           *string    `json:"goal_title,omitempty"`
	ExpectedCadence     string     `json:"expected_cadence"`
	LastHumanActivityAt *time.Time `json:"last_human_activity_at"`
	OpenNextAction      bool       `json:"open_next_action"`
	MilestoneDone       int64      `json:"milestone_done"`
	MilestoneTotal      int64      `json:"milestone_total"`
}

// GoalMilestones is the per-goal milestone progress used by the goals[]
// rollup. The projects' momentum rollup is assembled by the caller from the
// ProjectMomentum slice (grouped on GoalID); this carries the milestone
// counts that have no project to hang off.
type GoalMilestones struct {
	ID             uuid.UUID `json:"id"`
	Title          string    `json:"title"`
	MilestoneDone  int64     `json:"milestone_done"`
	MilestoneTotal int64     `json:"milestone_total"`
}

// AreaActivity is one active area's live human-activity signal for the
// areas[] neglect rollup. LastHumanActivityAt is nil when no human event is
// scoped to any project under the area.
type AreaActivity struct {
	Slug                string     `json:"slug"`
	Name                string     `json:"name"`
	LastHumanActivityAt *time.Time `json:"last_human_activity_at"`
}

// Momentum returns the live momentum signal for every candidate project —
// status in_progress|planned with an expected_cadence set. Read-only: it
// runs one SELECT and computes nothing it stores.
func (s *Store) Momentum(ctx context.Context) ([]ProjectMomentum, error) {
	rows, err := s.q.ProjectMomentum(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying project momentum: %w", err)
	}
	out := make([]ProjectMomentum, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = ProjectMomentum{
			Slug:                r.Slug,
			Title:               r.Title,
			GoalID:              r.GoalID,
			GoalTitle:           r.GoalTitle,
			ExpectedCadence:     deref(r.ExpectedCadence),
			LastHumanActivityAt: asTime(r.LastHumanActivityAt),
			OpenNextAction:      r.OpenNextAction != nil && *r.OpenNextAction,
			MilestoneDone:       r.MilestoneDone,
			MilestoneTotal:      r.MilestoneTotal,
		}
	}
	return out, nil
}

// ActiveGoalMilestones returns milestone progress for every in_progress goal,
// for the goals[] rollup. Read-only.
func (s *Store) ActiveGoalMilestones(ctx context.Context) ([]GoalMilestones, error) {
	rows, err := s.q.ActiveGoalMilestones(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying active goal milestones: %w", err)
	}
	out := make([]GoalMilestones, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = GoalMilestones{
			ID:             r.ID,
			Title:          r.Title,
			MilestoneDone:  r.MilestoneDone,
			MilestoneTotal: r.MilestoneTotal,
		}
	}
	return out, nil
}

// ActiveAreaActivity returns the live human-activity signal for every active
// PARA area, for the areas[] neglect rollup. Read-only.
func (s *Store) ActiveAreaActivity(ctx context.Context) ([]AreaActivity, error) {
	rows, err := s.q.ActiveAreaActivity(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying active area activity: %w", err)
	}
	out := make([]AreaActivity, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = AreaActivity{
			Slug:                r.Slug,
			Name:                r.Name,
			LastHumanActivityAt: asTime(r.LastHumanActivityAt),
		}
	}
	return out, nil
}

// Stalled reports whether a project is behind its expected cadence: it has
// an open next action AND its last human activity is older than 2× the
// cadence period (or it has never had human activity at all). A project with
// no open next action is "待規劃" — work to plan, not work overdue — and is
// never stalled. cadence is one of daily|weekly|biweekly|monthly; an
// unrecognised value (cadenceDays miss → 0 days) yields false.
//
// now is passed in (not read from the clock) so the decision is a pure
// function of its inputs and unit-testable against hand-computed instants.
func Stalled(lastHuman *time.Time, cadence string, openNextAction bool, now time.Time) bool {
	if !openNextAction {
		return false
	}
	days, ok := cadenceDays[cadence]
	if !ok || days <= 0 {
		return false
	}
	threshold := time.Duration(stalledFactor*days) * 24 * time.Hour
	if lastHuman == nil {
		// An open project that has never seen human activity is stalled the
		// moment it has been a candidate past its threshold. With no instant
		// to measure against we treat "never" as past any threshold.
		return true
	}
	return now.Sub(*lastHuman) > threshold
}

// AreaNeglected reports whether an area has had no human activity across all
// its projects for longer than AreaNeglectedThreshold. An area with no human
// activity at all (lastHuman == nil) is neglected. now is passed in for
// pure-function testability.
func AreaNeglected(lastHuman *time.Time, now time.Time) bool {
	if lastHuman == nil {
		return true
	}
	return now.Sub(*lastHuman) > AreaNeglectedThreshold
}

// DaysSince returns whole calendar days between lastHuman and now, or nil
// when there is no human activity. Truncated toward zero (a 36-hour gap is
// 1 day). Surfaced alongside the stalled flag so the owner sees the raw gap.
func DaysSince(lastHuman *time.Time, now time.Time) *int {
	if lastHuman == nil {
		return nil
	}
	d := int(now.Sub(*lastHuman).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return &d
}

// asTime converts the interface{} a nullable max()-over-derived-table column
// scans into (sqlc cannot resolve its concrete type through the LEFT JOIN) to
// a *time.Time. A SQL NULL arrives as nil; a timestamptz as time.Time.
func asTime(v interface{}) *time.Time {
	t, ok := v.(time.Time)
	if !ok {
		return nil
	}
	return &t
}

// deref returns the string a *string points to, or "" when nil. The
// expected_cadence column is nullable in the schema but every project_progress
// candidate row has it set (the query's WHERE excludes NULL), so the empty
// fallback is defensive only.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
