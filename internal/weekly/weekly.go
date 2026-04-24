// Package weekly computes a weekly review snapshot on demand from primary
// state. It replaces the former internal/synthesis (read layer over the
// syntheses table) and internal/consolidation (write layer that produced
// rows) pair with a single pure-function package.
//
// Rationale for deleting the stored-snapshot design:
//
//   - The only consumer was a retrospective history viewer that was never
//     wired up to a live UI.
//   - Primary state (todo_items, agent_notes, learning sessions) is
//     effectively append-only in koopa's model, so recomputing a past
//     week from primary state yields the same result as replaying a
//     stored snapshot.
//   - Compute is cheap — indexed queries + Go aggregation over a week's
//     worth of data is milliseconds.
//
// This package mirrors internal/daily in philosophy: take primary stores,
// compute a view, return it. No DB table, no Store, no Create/ByWeek API.
package weekly

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/todo"
)

// Review is the structured output of Compute for a single week.
type Review struct {
	WeekStart       string         `json:"week_start"`
	WeekEnd         string         `json:"week_end"`
	TodosCreated    int            `json:"todos_created"`
	TodosCompleted  []TodoRef      `json:"todos_completed"`
	JournalCount    int            `json:"journal_count"`
	JournalKinds    map[string]int `json:"journal_kinds"`
	SessionCount    int            `json:"session_count"`
	SessionDomains  []string       `json:"session_domains"`
	ConceptsTouched int            `json:"concepts_touched"`
	Computed        ComputedStats  `json:"computed"`
}

// TodoRef is a lightweight reference to a completed todo item inside
// a weekly review. Minimal — full detail stays in primary state.
type TodoRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Area  string `json:"area,omitempty"`
}

// ComputedStats are derived metrics for a week.
type ComputedStats struct {
	TotalMinutes     int     `json:"total_minutes,omitempty"`
	DistinctWorkDays int     `json:"distinct_work_days"`
	CompletionRate   float64 `json:"completion_rate,omitempty"`
}

// Compute reads primary state for the [weekStart, weekEnd) window and
// returns a Review. The only side effects are the read queries through
// the concrete stores.
//
// weekStart must be a Monday at 00:00:00 in the caller's location.
// weekEnd is computed as weekStart + 7 days.
//
// The stores are passed as concrete pointers, not interfaces. There is
// exactly one production implementation of each, integration tests use
// testcontainers against a real PostgreSQL, and no other consumer needs
// a different shape — see .claude/rules/interfaces.md.
func Compute(
	ctx context.Context,
	todos *todo.Store,
	notes *note.Store,
	sessions *learning.Store,
	weekStart time.Time,
) (Review, error) {
	if err := validateWeekStart(weekStart); err != nil {
		return Review{}, err
	}
	weekEnd := weekStart.AddDate(0, 0, 7)

	completedAll, err := todos.CompletedItemsDetailSince(ctx, weekStart)
	if err != nil {
		return Review{}, fmt.Errorf("reading completed todo items: %w", err)
	}
	completed := filterCompletedToWeek(completedAll, weekStart, weekEnd)

	createdAll, err := todos.ItemsCreatedSince(ctx, weekStart)
	if err != nil {
		return Review{}, fmt.Errorf("reading created todo items: %w", err)
	}
	createdInWeek := 0
	for i := range createdAll {
		if createdAll[i].CreatedAt.Before(weekEnd) {
			createdInWeek++
		}
	}

	weekNotes, err := notes.NotesInRange(ctx, weekStart, weekEnd, nil, nil)
	if err != nil {
		return Review{}, fmt.Errorf("reading agent notes: %w", err)
	}

	sessionsAll, err := sessions.RecentSessions(ctx, nil, weekStart, 500)
	if err != nil {
		return Review{}, fmt.Errorf("reading learning sessions: %w", err)
	}
	weekSessions := filterSessionsToWeek(sessionsAll, weekStart, weekEnd)

	noteKinds := map[string]int{}
	for i := range weekNotes {
		noteKinds[string(weekNotes[i].Kind)]++
	}

	todoRefs := make([]TodoRef, len(completed))
	for i := range completed {
		todoRefs[i] = TodoRef{
			ID:    completed[i].ID,
			Title: completed[i].Title,
			Area:  completed[i].ProjectTitle,
		}
	}

	return Review{
		WeekStart:       weekStart.Format(time.DateOnly),
		WeekEnd:         weekEnd.Format(time.DateOnly),
		TodosCreated:    createdInWeek,
		TodosCompleted:  todoRefs,
		JournalCount:    len(weekNotes),
		JournalKinds:    noteKinds,
		SessionCount:    len(weekSessions),
		SessionDomains:  distinctDomains(weekSessions),
		ConceptsTouched: 0, // reserved for future slice — requires attempt_observations scan
		Computed: ComputedStats{
			DistinctWorkDays: distinctWorkDaysFrom(completed),
		},
	}, nil
}

// MondayOf returns the Monday of the ISO week containing t, in t's
// location, at 00:00:00. Use this to normalize a week boundary before
// calling Compute.
func MondayOf(t time.Time) time.Time {
	weekday := t.Weekday()
	if weekday == time.Sunday {
		weekday = 7
	}
	monday := t.AddDate(0, 0, -int(weekday-time.Monday))
	return time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, t.Location())
}

// WeekKey returns the ISO 8601 week key "YYYY-Www" for the week
// containing t. Useful for labeling Review output.
func WeekKey(t time.Time) string {
	year, week := t.ISOWeek()
	return fmt.Sprintf("%04d-W%02d", year, week)
}

func validateWeekStart(weekStart time.Time) error {
	if weekStart.Weekday() != time.Monday {
		return fmt.Errorf("weekly: weekStart must be a Monday, got %s", weekStart.Weekday())
	}
	if h, m, s := weekStart.Clock(); h != 0 || m != 0 || s != 0 {
		return fmt.Errorf("weekly: weekStart must be at 00:00:00, got %02d:%02d:%02d", h, m, s)
	}
	return nil
}

// completedRef is a local shape used by the week-window filter; callers
// never see it.
type completedRef struct {
	ID           string
	Title        string
	ProjectTitle string
	CompletedAt  time.Time
}

type sessionRef struct {
	ID     string
	Domain string
}

func filterCompletedToWeek(all []todo.CompletedDetail, weekStart, weekEnd time.Time) []completedRef {
	out := make([]completedRef, 0, len(all))
	for i := range all {
		t := &all[i]
		if t.CompletedAt == nil || t.CompletedAt.Before(weekStart) || !t.CompletedAt.Before(weekEnd) {
			continue
		}
		out = append(out, completedRef{
			ID:           t.ID.String(),
			Title:        t.Title,
			ProjectTitle: t.ProjectTitle,
			CompletedAt:  *t.CompletedAt,
		})
	}
	return out
}

func filterSessionsToWeek(all []learning.Session, weekStart, weekEnd time.Time) []sessionRef {
	out := make([]sessionRef, 0, len(all))
	for i := range all {
		s := &all[i]
		if s.StartedAt.Before(weekStart) || !s.StartedAt.Before(weekEnd) {
			continue
		}
		out = append(out, sessionRef{
			ID:     s.ID.String(),
			Domain: s.Domain,
		})
	}
	return out
}

func distinctDomains(sessions []sessionRef) []string {
	seen := map[string]struct{}{}
	for i := range sessions {
		seen[sessions[i].Domain] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func distinctWorkDaysFrom(completed []completedRef) int {
	days := map[string]struct{}{}
	for i := range completed {
		days[completed[i].CompletedAt.Format(time.DateOnly)] = struct{}{}
	}
	return len(days)
}
