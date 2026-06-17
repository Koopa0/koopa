// Copyright 2026 Koopa. All rights reserved.

package learning

import (
	"fmt"
	"time"
)

// NextTargetWindowDays is the lookback for the session-independent "next
// target" recommendation. It matches the MCP recommender's window so both
// surfaces reason over the same slice of recent practice.
const NextTargetWindowDays = 30

// NextTarget is a single session-independent practice recommendation for the
// admin "Next up" card. Empty is true when there is nothing to recommend
// (no weakness signal in the window); the card renders an empty state from
// Reason without needing a 404.
//
// This is deliberately NOT the MCP Candidate shape. The MCP recommender is
// session-scoped and fans out a variation graph into a ranked list; this card
// answers a different question — "with no session open, what single concept
// most deserves practice next?" — off the severity-ordered weakness signal.
type NextTarget struct {
	// Empty reports that there is no recommendation. When true, ConceptSlug /
	// ConceptName / Domain are zero and Reason explains the empty state.
	Empty bool `json:"empty"`

	ConceptSlug string `json:"concept_slug,omitempty"`
	ConceptName string `json:"concept_name,omitempty"`
	Domain      string `json:"domain,omitempty"`

	// MasteryStage is the concept's stage derived from its weakness signal in
	// the window. A recommended concept always carries weakness observations,
	// so it is "struggling" once past the observation floor and "developing"
	// below it — never "solid".
	MasteryStage MasteryStage `json:"mastery_stage,omitempty"`

	// Severity is the dominant severity label of the concept's weakness
	// observations: critical > moderate > minor. Empty only when no severity
	// counts are set, which the SQL ordering makes the least-urgent case.
	Severity string `json:"severity,omitempty"`

	// DaysSincePractice is whole days since the most recent weakness
	// observation on this concept, computed against the recommendation time.
	DaysSincePractice int `json:"days_since_practice,omitempty"`

	// Reason is a pre-rendered one-line human sentence. Always populated —
	// both for a recommendation and for the empty state.
	Reason string `json:"reason"`
}

// SelectNextTarget picks the single concept the admin "Next up" card should
// surface next, from a severity-ordered weakness slice, and renders a
// one-line human reason.
//
// weaknesses MUST be ordered as WeaknessAnalysis returns them — critical_count
// DESC, then occurrence_count DESC — so the first row is the most urgent
// concept and the function can take the head without re-sorting. now is the
// reference time for days-since-practice (injected so tests are deterministic).
//
// An empty slice yields NextTarget{Empty: true} with a reason the card can
// show directly: there is no weakness signal to recommend against.
func SelectNextTarget(weaknesses []WeaknessRow, now time.Time) NextTarget {
	if len(weaknesses) == 0 {
		return NextTarget{
			Empty:  true,
			Reason: fmt.Sprintf("no concepts need practice in the last %d days — nothing to recommend yet", NextTargetWindowDays),
		}
	}

	w := &weaknesses[0]
	severity := dominantWeaknessSeverity(w)
	stage := DeriveMasteryStage(w.OccurrenceCount, 0, 0)
	days := daysSince(w.LastSeenAt, now)

	return NextTarget{
		Empty:             false,
		ConceptSlug:       w.ConceptSlug,
		ConceptName:       w.ConceptName,
		Domain:            w.Domain,
		MasteryStage:      stage,
		Severity:          severity,
		DaysSincePractice: days,
		Reason:            nextTargetReason(w, severity, days),
	}
}

// dominantWeaknessSeverity picks the severity label to report for a weakness
// concept: critical > moderate > minor; the first non-zero count wins so
// "one critical" outranks "many minors". Returns "" only when no severity
// count is set.
func dominantWeaknessSeverity(w *WeaknessRow) string {
	switch {
	case w.CriticalCount > 0:
		return "critical"
	case w.ModerateCount > 0:
		return "moderate"
	case w.MinorCount > 0:
		return "minor"
	default:
		return ""
	}
}

// daysSince returns whole days between then and now, floored at zero. A
// future then (clock skew or an observation timestamped ahead) yields 0
// rather than a negative count.
func daysSince(then, now time.Time) int {
	d := now.Sub(then)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// nextTargetReason renders the one-line human sentence for a recommended
// concept. It names the concept, the dominant weakness severity, how many
// times it surfaced in the window, and how stale the last attempt is so
// Koopa can decide at a glance whether to practice it now.
func nextTargetReason(w *WeaknessRow, severity string, days int) string {
	severityPhrase := "weakness"
	if severity != "" {
		severityPhrase = severity + " weakness"
	}

	recency := "last practiced today"
	switch {
	case days == 1:
		recency = "last practiced yesterday"
	case days > 1:
		recency = fmt.Sprintf("last practiced %d days ago", days)
	}

	if w.OccurrenceCount == 1 {
		return fmt.Sprintf("%s — a %s surfaced once in the last %d days, %s",
			w.ConceptName, severityPhrase, NextTargetWindowDays, recency)
	}
	return fmt.Sprintf("%s — a %s surfaced %d times in the last %d days, %s",
		w.ConceptName, severityPhrase, w.OccurrenceCount, NextTargetWindowDays, recency)
}
