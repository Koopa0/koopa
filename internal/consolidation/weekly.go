package consolidation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/synthesis"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// ComputedBy is the label written into syntheses.computed_by for
// weekly consolidation runs. Includes the invocation mode so the
// historical record preserves "was this a cron run or manual replay".
const (
	ComputedByWeeklyManual = "consolidation:weekly:manual"
	ComputedByWeeklyCron   = "consolidation:weekly:cron"
)

// RunWeeklyResult summarizes what a single RunWeekly invocation did.
// The caller (admin endpoint) returns it to the client so Koopa can
// verify a manual trigger actually produced a snapshot — critically,
// the caller can distinguish "new row written" from "already up to
// date" (no-op).
type RunWeeklyResult struct {
	WeekKey      string                     `json:"week_key"`
	WeekStart    time.Time                  `json:"week_start"`
	WeekEnd      time.Time                  `json:"week_end"`
	Created      bool                       `json:"created"`
	EvidenceHash string                     `json:"evidence_hash"`
	EvidenceSize int                        `json:"evidence_size"`
	Body         synthesis.WeeklyReviewBody `json:"body"`
}

// RunWeekly reads primary state for the week containing weekStart and
// writes a synthesis row capturing that week as a historical snapshot.
//
// Determinism: given the same primary state and the same weekStart,
// this function produces the same body and the same evidence_hash.
// ON CONFLICT DO NOTHING on the unique index (subject_type, subject_key,
// kind, evidence_hash) ensures repeated invocation is a no-op.
//
// Historical accumulation: if primary state has drifted since the last
// run (e.g., a task was backdated, a journal entry was added to the
// week), the evidence set differs, the hash differs, and a new
// synthesis row is inserted alongside the old one. Neither is deleted.
// A reader calling RecentByKind sees the timeline.
//
// Caller contract: MUST pass a weekStart that is a Monday at 00:00 in
// the user's timezone, produced by synthesis.MondayOf. Non-Monday
// input is rejected up front — consolidating on an arbitrary day
// would produce weeks that overlap at the boundaries.
//
// This function does not call out to LLMs, does not dispatch MCP
// tools, and does not write to any primary table. The only INSERT
// is the synthesis row, via synth.Create.
func RunWeekly(
	ctx context.Context,
	primary *PrimaryReader,
	synth *synthesis.Store,
	weekStart time.Time,
	computedBy string,
) (*RunWeeklyResult, error) {
	if err := validateWeekStart(weekStart); err != nil {
		return nil, err
	}
	weekEnd := weekStart.AddDate(0, 0, 7)
	weekKey := synthesis.WeekKey(weekStart)

	state, err := readWeeklyPrimary(ctx, primary, weekStart, weekEnd)
	if err != nil {
		return nil, err
	}

	body := buildWeeklyBody(weekStart, weekEnd, state)
	evidence := buildWeeklyEvidence(state)
	evidenceHash := synthesis.ComputeEvidenceHash(evidence)

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling weekly body: %w", err)
	}

	weekKeyPtr := weekKey
	_, createErr := synth.Create(ctx, &synthesis.CreateParams{
		SubjectType:  synthesis.SubjectWeek,
		SubjectKey:   &weekKeyPtr,
		Kind:         synthesis.KindWeeklyReview,
		Body:         bodyJSON,
		Evidence:     evidence,
		EvidenceHash: evidenceHash,
		ComputedBy:   computedBy,
	})

	created := true
	if createErr != nil {
		if errors.Is(createErr, synthesis.ErrNotFound) {
			// ON CONFLICT DO NOTHING triggered — same evidence set
			// was already recorded. Not an error, just a no-op.
			created = false
		} else {
			return nil, fmt.Errorf("writing synthesis: %w", createErr)
		}
	}

	return &RunWeeklyResult{
		WeekKey:      weekKey,
		WeekStart:    weekStart,
		WeekEnd:      weekEnd,
		Created:      created,
		EvidenceHash: evidenceHash,
		EvidenceSize: len(evidence),
		Body:         body,
	}, nil
}

// validateWeekStart enforces the weekStart invariant: Monday at
// 00:00:00 in the caller's timezone. Non-Monday input would produce
// overlapping week boundaries; non-midnight input would shift the
// range and silently miss tasks at day edges.
func validateWeekStart(weekStart time.Time) error {
	if weekStart.Weekday() != time.Monday {
		return fmt.Errorf("consolidation: weekStart must be a Monday, got %s", weekStart.Weekday())
	}
	if h, m, s := weekStart.Clock(); h != 0 || m != 0 || s != 0 {
		return fmt.Errorf("consolidation: weekStart must be at 00:00:00, got %02d:%02d:%02d", h, m, s)
	}
	return nil
}

// weeklyPrimaryState is the read-only snapshot of primary state used
// to build a weekly_review body. Holds only what contributed to the
// evidence set; derived metrics are computed in buildWeeklyBody.
type weeklyPrimaryState struct {
	Completed     []completedTaskRef
	CreatedInWeek int
	Journals      []journal.Entry
	Sessions      []learningSessionRef
}

// readWeeklyPrimary reads tasks, journal entries, and learning
// sessions for the target week window. It filters each stream to
// the [weekStart, weekEnd) half-open interval — the boundary rule
// is "Monday inclusive, next Monday exclusive".
//
// CompletedTasksDetailSince / TasksCreatedSince / RecentSessions all
// take an open-ended "since" argument, so this function applies the
// upper bound in Go instead of at the query layer. That keeps the
// existing store APIs unchanged while still producing a deterministic
// week-scoped snapshot.
func readWeeklyPrimary(
	ctx context.Context,
	primary *PrimaryReader,
	weekStart, weekEnd time.Time,
) (*weeklyPrimaryState, error) {
	allCompleted, err := primary.Tasks.CompletedTasksDetailSince(ctx, weekStart)
	if err != nil {
		return nil, fmt.Errorf("reading completed tasks: %w", err)
	}
	completed := filterCompletedToWeek(allCompleted, weekStart, weekEnd)

	allCreated, err := primary.Tasks.TasksCreatedSince(ctx, weekStart)
	if err != nil {
		return nil, fmt.Errorf("reading created tasks: %w", err)
	}
	createdInWeek := 0
	for i := range allCreated {
		if allCreated[i].CreatedAt.Before(weekEnd) {
			createdInWeek++
		}
	}

	journals, err := primary.Journal.EntriesByDateRange(ctx, weekStart, weekEnd, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("reading journal entries: %w", err)
	}

	sessions, err := primary.Learning.RecentSessions(ctx, nil, weekStart, 500)
	if err != nil {
		return nil, fmt.Errorf("reading learning sessions: %w", err)
	}
	weekSessions := filterSessionsToWeek(sessions, weekStart, weekEnd)

	return &weeklyPrimaryState{
		Completed:     completed,
		CreatedInWeek: createdInWeek,
		Journals:      journals,
		Sessions:      weekSessions,
	}, nil
}

func filterCompletedToWeek(
	all []task.CompletedTaskDetail,
	weekStart, weekEnd time.Time,
) []completedTaskRef {
	out := make([]completedTaskRef, 0, len(all))
	for i := range all {
		t := &all[i]
		if t.CompletedAt == nil || t.CompletedAt.Before(weekStart) || !t.CompletedAt.Before(weekEnd) {
			continue
		}
		out = append(out, completedTaskRef{
			ID:           t.ID.String(),
			Title:        t.Title,
			ProjectTitle: t.ProjectTitle,
			CompletedAt:  *t.CompletedAt,
		})
	}
	return out
}

func filterSessionsToWeek(
	all []learning.Session,
	weekStart, weekEnd time.Time,
) []learningSessionRef {
	out := make([]learningSessionRef, 0, len(all))
	for i := range all {
		s := &all[i]
		if s.StartedAt.Before(weekStart) || !s.StartedAt.Before(weekEnd) {
			continue
		}
		out = append(out, learningSessionRef{
			ID:     s.ID.String(),
			Domain: s.Domain,
		})
	}
	return out
}

// buildWeeklyBody assembles the structured WeeklyReviewBody from the
// read-only primary state. Pure function, no I/O. Same input always
// produces the same output.
func buildWeeklyBody(
	weekStart, weekEnd time.Time,
	state *weeklyPrimaryState,
) synthesis.WeeklyReviewBody {
	journalKinds := map[string]int{}
	for i := range state.Journals {
		journalKinds[string(state.Journals[i].Kind)]++
	}

	tasksCompletedForBody := make([]synthesis.WeeklyTaskRef, len(state.Completed))
	for i := range state.Completed {
		tasksCompletedForBody[i] = synthesis.WeeklyTaskRef{
			ID:    state.Completed[i].ID,
			Title: state.Completed[i].Title,
			Area:  state.Completed[i].ProjectTitle,
		}
	}

	return synthesis.WeeklyReviewBody{
		WeekStart:       weekStart.Format(time.DateOnly),
		WeekEnd:         weekEnd.Format(time.DateOnly),
		TasksCreated:    state.CreatedInWeek,
		TasksCompleted:  tasksCompletedForBody,
		JournalCount:    len(state.Journals),
		JournalKinds:    journalKinds,
		SessionCount:    len(state.Sessions),
		SessionDomains:  distinctDomains(state.Sessions),
		ConceptsTouched: 0, // reserved for future slice — requires attempt_observations scan
		Computed: synthesis.WeeklyComputedStats{
			DistinctWorkDays: distinctWorkDaysFrom(state.Completed),
		},
	}
}

// buildWeeklyEvidence produces the flat list of evidence refs that
// identify WHICH primary rows contributed to the body. Pure function;
// order is determined by input order but the hash is order-invariant
// (ComputeEvidenceHash sorts before hashing).
//
// Evidence deliberately excludes derived metrics and row contents —
// the hash answers "is this the same set?", not "is this the same
// data?". Two runs with the same row set but different row contents
// (e.g. a task title was edited) still produce the same hash,
// because the body captures the new data in a different column.
func buildWeeklyEvidence(state *weeklyPrimaryState) []synthesis.EvidenceRef {
	out := make([]synthesis.EvidenceRef, 0, len(state.Completed)+len(state.Journals)+len(state.Sessions))
	for i := range state.Completed {
		out = append(out, synthesis.EvidenceRef{
			Type: "task",
			ID:   state.Completed[i].ID,
		})
	}
	for i := range state.Journals {
		out = append(out, synthesis.EvidenceRef{
			Type: "journal",
			ID:   fmt.Sprintf("%d", state.Journals[i].ID),
		})
	}
	for i := range state.Sessions {
		out = append(out, synthesis.EvidenceRef{
			Type: "session",
			ID:   state.Sessions[i].ID,
		})
	}
	return out
}

// completedTaskRef and learningSessionRef are tiny internal structs
// for collecting evidence within a single RunWeekly call. Not
// exported — consumers work with synthesis.EvidenceRef at the
// boundary. Defined locally so consolidation does not leak task or
// learning package types into its own API.
type completedTaskRef struct {
	ID           string
	Title        string
	ProjectTitle string
	CompletedAt  time.Time
}

type learningSessionRef struct {
	ID     string
	Domain string
}

func distinctDomains(sessions []learningSessionRef) []string {
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

func distinctWorkDaysFrom(completed []completedTaskRef) int {
	days := map[string]struct{}{}
	for i := range completed {
		days[completed[i].CompletedAt.Format(time.DateOnly)] = struct{}{}
	}
	return len(days)
}
