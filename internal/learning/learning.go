// Package learning provides learning session orchestration.
//
// A session has explicit start/end, a mode, and contains attempts.
// The session produces a journal entry, not the other way around.
package learning

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound     = errors.New("learning: not found")
	ErrConflict     = errors.New("learning: conflict")
	ErrActiveExists = errors.New("learning: active session exists")
	ErrNoActive     = errors.New("learning: no active session")
	ErrAlreadyEnded = errors.New("learning: session already ended")
	// ErrInvalidInput marks caller-side input validation failures (bad UUID,
	// oversized metadata, unknown relation_type, etc). Wrapped with %w so
	// callers can classify validation failures for logging/metrics via
	// errors.Is, even if the current handler stack doesn't branch on it.
	ErrInvalidInput = errors.New("learning: invalid input")
)

// Mode represents a learning session mode.
type Mode string

const (
	ModeRetrieval Mode = "retrieval"
	ModePractice  Mode = "practice"
	ModeMixed     Mode = "mixed"
	ModeReview    Mode = "review"
	ModeReading   Mode = "reading"
)

// Session represents a learning session.
type Session struct {
	ID              uuid.UUID  `json:"id"`
	Domain          string     `json:"domain"`
	Mode            Mode       `json:"mode"`
	JournalID       *int64     `json:"journal_id,omitempty"`
	DailyPlanItemID *uuid.UUID `json:"daily_plan_item_id,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Attempt represents an attempt on a learning item within a session.
type Attempt struct {
	ID              uuid.UUID  `json:"id"`
	ItemID          uuid.UUID  `json:"item_id"`
	SessionID       *uuid.UUID `json:"session_id,omitempty"`
	AttemptNumber   int32      `json:"attempt_number"`
	Outcome         string     `json:"outcome"`
	DurationMinutes *int32     `json:"duration_minutes,omitempty"`
	StuckAt         *string    `json:"stuck_at,omitempty"`
	ApproachUsed    *string    `json:"approach_used,omitempty"`
	AttemptedAt     time.Time  `json:"attempted_at"`
	ItemTitle       string     `json:"item_title"`
	ItemExternalID  *string    `json:"item_external_id,omitempty"`
}

// Observation represents a learning signal on a concept.
type Observation struct {
	ID          uuid.UUID `json:"id"`
	AttemptID   uuid.UUID `json:"attempt_id"`
	ConceptID   uuid.UUID `json:"concept_id"`
	SignalType  string    `json:"signal_type"`
	Category    string    `json:"category"`
	Severity    *string   `json:"severity,omitempty"`
	Detail      *string   `json:"detail,omitempty"`
	ConceptSlug string    `json:"concept_slug"`
	ConceptName string    `json:"concept_name"`
}

// MapOutcome maps semantic outcome input to the schema enum based on session mode.
func MapOutcome(mode Mode, semantic string) (string, error) {
	// Accept raw enum values directly.
	switch semantic {
	case "solved_independent", "solved_with_hint", "solved_after_solution",
		"completed", "completed_with_support", "incomplete", "gave_up":
		return semantic, nil
	}

	// Map semantic input based on mode.
	switch mode {
	case ModePractice, ModeRetrieval, ModeMixed, ModeReview:
		return mapProblemSolving(semantic)
	case ModeReading:
		return mapImmersive(semantic)
	default:
		return "", fmt.Errorf("unknown session mode %q", mode)
	}
}

func mapProblemSolving(s string) (string, error) {
	switch s {
	case "got it", "solved it", "nailed it":
		return "solved_independent", nil
	case "needed help", "needed a hint", "got help":
		return "solved_with_hint", nil
	case "saw answer", "saw the answer", "saw the answer first":
		return "solved_after_solution", nil
	case "didn't finish", "not done":
		return "incomplete", nil
	case "gave up", "stuck":
		return "gave_up", nil
	default:
		return "", fmt.Errorf("unrecognized outcome %q for practice/retrieval mode", s)
	}
}

func mapImmersive(s string) (string, error) {
	switch s {
	case "got it", "finished", "done":
		return "completed", nil
	case "needed help", "needed support":
		return "completed_with_support", nil
	case "didn't finish", "not done":
		return "incomplete", nil
	case "gave up", "stuck":
		return "gave_up", nil
	default:
		return "", fmt.Errorf("unrecognized outcome %q for reading mode", s)
	}
}
