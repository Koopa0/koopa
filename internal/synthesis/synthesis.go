// Package synthesis provides the historical observation layer for
// koopa0.dev derived views.
//
// A Synthesis is a frozen snapshot of what a derived view looked like
// at a specific moment, based on a specific evidence set. Syntheses
// are written by secondary consolidation processes — never by live
// handlers — and read by retrospective query tools. Old rows are
// never updated and never invalidated.
//
// This is not a cache:
//
//   - The reader never falls through to live compute on a miss.
//   - There is no TTL and no staleness semantic.
//   - The same (subject, kind) accumulates rows over time as primary
//     state drifts and evidence_hash changes.
//   - Live handlers (weekly_summary, goal_progress, etc.) MUST NOT
//     import this package. A runtime test in this package verifies
//     that running weekly_summary leaves the syntheses table empty.
//
// First slice constraint: only subject_type=week and kind=weekly_review
// are wired end-to-end. Schema CHECK constraints enforce this; future
// slices extend via ALTER TABLE.
package synthesis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// SubjectType is the taxonomy of what a Synthesis describes.
type SubjectType string

const (
	// SubjectWeek is a calendar week identified by ISO week key.
	SubjectWeek SubjectType = "week"
)

// Kind is the taxonomy of derived views that can be snapshot.
type Kind string

const (
	// KindWeeklyReview is a snapshot of a week's tasks/journal/sessions
	// aggregate. Body type: WeeklyReviewBody.
	KindWeeklyReview Kind = "weekly_review"
)

// EvidenceRef is one primary-state id that contributed to a Synthesis.
// Shape is kept minimal so the evidence JSONB stays small and the
// canonical hash is stable across runs.
type EvidenceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Synthesis is one row in the syntheses table.
type Synthesis struct {
	ID           uuid.UUID       `json:"id"`
	SubjectType  SubjectType     `json:"subject_type"`
	SubjectID    *uuid.UUID      `json:"subject_id,omitempty"`
	SubjectKey   *string         `json:"subject_key,omitempty"`
	Kind         Kind            `json:"kind"`
	Body         json.RawMessage `json:"body"`
	Evidence     []EvidenceRef   `json:"evidence"`
	EvidenceHash string          `json:"evidence_hash"`
	ComputedAt   time.Time       `json:"computed_at"`
	ComputedBy   string          `json:"computed_by"`
}

// CreateParams are the arguments for Store.Create. The caller (always
// a secondary consolidation process) is responsible for building the
// Body, collecting the Evidence, and computing the EvidenceHash via
// ComputeEvidenceHash. The store does not recompute — keeping that
// logic in the caller means the same helper is used across future
// consolidation phases and any manual-replay tooling.
type CreateParams struct {
	SubjectType  SubjectType
	SubjectID    *uuid.UUID
	SubjectKey   *string
	Kind         Kind
	Body         json.RawMessage
	Evidence     []EvidenceRef
	EvidenceHash string
	ComputedBy   string
}

// WeeklyReviewBody is the structured payload for kind=weekly_review.
// It is a typed Go struct marshaled to JSONB at write time and
// unmarshaled back at read time. Never a free-text LLM dump.
//
// The fields mirror what weeklySummary surfaces, deliberately — the
// historical snapshot should carry the same shape a live reader would
// see, so a retrospective viewer can compare "this week now" against
// "that week then" without format reconciliation.
type WeeklyReviewBody struct {
	WeekStart       string              `json:"week_start"`
	WeekEnd         string              `json:"week_end"`
	TasksCreated    int                 `json:"tasks_created"`
	TasksCompleted  []WeeklyTaskRef     `json:"tasks_completed"`
	JournalCount    int                 `json:"journal_count"`
	JournalKinds    map[string]int      `json:"journal_kinds"`
	SessionCount    int                 `json:"session_count"`
	SessionDomains  []string            `json:"session_domains"`
	ConceptsTouched int                 `json:"concepts_touched"`
	Computed        WeeklyComputedStats `json:"computed"`
}

// WeeklyTaskRef is a lightweight reference to a completed task inside
// a weekly snapshot. Deliberately minimal — full task detail lives in
// the primary table; the snapshot only needs enough to render a list.
type WeeklyTaskRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Area  string `json:"area,omitempty"`
}

// WeeklyComputedStats are the derived metrics for a week. These are
// the numbers that would not survive a later re-query of primary
// state because primary rows might be edited, backdated, or archived.
type WeeklyComputedStats struct {
	TotalMinutes     int     `json:"total_minutes,omitempty"`
	DistinctWorkDays int     `json:"distinct_work_days"`
	CompletionRate   float64 `json:"completion_rate,omitempty"`
}

var (
	// ErrNotFound indicates no synthesis row matched the query.
	ErrNotFound = errors.New("synthesis: not found")
)

// ComputeEvidenceHash returns the canonical SHA-256 hex digest of the
// evidence set. Canonicalization: sort by (type, id), marshal to JSON,
// hash. Stable across runs and platforms. Empty input yields the hash
// of "[]".
func ComputeEvidenceHash(evidence []EvidenceRef) string {
	// Copy to avoid mutating the caller's slice.
	sorted := make([]EvidenceRef, len(evidence))
	copy(sorted, evidence)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].ID < sorted[j].ID
	})

	// json.Marshal of an empty slice produces "null", not "[]", which
	// would make the empty-evidence hash ambiguous. Normalize here.
	if len(sorted) == 0 {
		sum := sha256.Sum256([]byte("[]"))
		return hex.EncodeToString(sum[:])
	}

	raw, err := json.Marshal(sorted)
	if err != nil {
		// json.Marshal of a []EvidenceRef should never fail — the
		// fields are plain strings. If it does, the caller has
		// constructed an impossible value, which is a programming
		// error, not a runtime condition.
		panic(fmt.Sprintf("synthesis: marshal evidence: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// WeekKey returns the ISO 8601 week key for the week containing t.
// Format: "YYYY-Www", e.g. "2026-W15". Stable across time zones as
// long as the caller passes a consistent location.
func WeekKey(t time.Time) string {
	year, week := t.ISOWeek()
	return fmt.Sprintf("%04d-W%02d", year, week)
}

// MondayOf returns the Monday of the ISO week containing t, in t's
// location, at 00:00:00. Used by consolidation to normalize a week
// boundary before querying primary state.
func MondayOf(t time.Time) time.Time {
	weekday := t.Weekday()
	if weekday == time.Sunday {
		weekday = 7
	}
	monday := t.AddDate(0, 0, -int(weekday-time.Monday))
	return time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, t.Location())
}
