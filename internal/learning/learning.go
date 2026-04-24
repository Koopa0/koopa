// Package learning provides learning session orchestration.
//
// A session has explicit start/end, a mode, and contains attempts.
// Ending a session optionally produces an agent_notes(kind=reflection) entry.
package learning

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for learning sessions, attempts,
// observations, concepts, and learning targets. FSRS spaced-repetition
// scheduling lives in the sibling package internal/learning/fsrs.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store using the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

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

// Domain is a learning domain (FK target for concepts, targets, sessions,
// plans). Closed set bootstrapped via migration 002, extended at runtime
// through propose_commitment(type=learning_domain).
type Domain struct {
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

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
	AgentNoteID     *uuid.UUID `json:"agent_note_id,omitempty"`
	DailyPlanItemID *uuid.UUID `json:"daily_plan_item_id,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Attempt represents an attempt on a learning target within a session.
//
// Attempt is the unified shape for all attempt-returning paths:
// RecordAttempt (write), AttemptsBySession / AttemptsByLearningTarget /
// AttemptsByConcept (read). Optional fields are populated only on the paths
// where they make sense — Difficulty and Matched are only set by
// AttemptsByConcept, Metadata is set by every read path but absent from
// write returns.
type Attempt struct {
	ID               uuid.UUID           `json:"id"`
	LearningTargetID uuid.UUID           `json:"learning_target_id"`
	SessionID        uuid.UUID           `json:"session_id"`
	AttemptNumber    int32               `json:"attempt_number"`
	Paradigm         Paradigm            `json:"paradigm"`
	Outcome          string              `json:"outcome"`
	DurationMinutes  *int32              `json:"duration_minutes,omitempty"`
	StuckAt          *string             `json:"stuck_at,omitempty"`
	ApproachUsed     *string             `json:"approach_used,omitempty"`
	AttemptedAt      time.Time           `json:"attempted_at"`
	Metadata         json.RawMessage     `json:"metadata,omitempty"`
	TargetTitle      string              `json:"target_title"`
	TargetExternalID *string             `json:"target_external_id,omitempty"`
	Difficulty       *string             `json:"difficulty,omitempty"`
	Matched          *MatchedObservation `json:"matched_observation,omitempty"`
}

// MatchedObservation describes the highest-priority observation that linked
// an attempt to a concept query. Populated only on AttemptsByConcept results;
// nil on AttemptsBySession / AttemptsByLearningTarget.
//
// Priority when an attempt has multiple observations on the same concept:
// signal weakness > improvement > mastery, then severity critical > moderate
// > minor. Selected by the SQL query, not in Go.
type MatchedObservation struct {
	Signal   string  `json:"signal"`
	Category string  `json:"category"`
	Severity *string `json:"severity,omitempty"`
	Detail   *string `json:"detail,omitempty"`
}

// Observation represents a learning signal on a concept.
//
// ConceptSlug and ConceptName are populated only by read-side query paths
// (e.g. ObservationsByAttempt). On direct write returns from RecordObservation
// they are empty — the INSERT returning clause does not join concepts. Both
// fields stay non-pointer string for JSON-shape stability across paths.
type Observation struct {
	ID          uuid.UUID `json:"id"`
	AttemptID   uuid.UUID `json:"attempt_id"`
	ConceptID   uuid.UUID `json:"concept_id"`
	SignalType  string    `json:"signal_type"`
	Category    string    `json:"category"`
	Severity    *string   `json:"severity,omitempty"`
	Detail      *string   `json:"detail,omitempty"`
	Confidence  string    `json:"confidence"`
	ConceptSlug string    `json:"concept_slug,omitempty"`
	ConceptName string    `json:"concept_name,omitempty"`
}

// Paradigm classifies an attempt outcome's vocabulary space. Matches the
// learning_attempts.paradigm CHECK in migrations/001.
type Paradigm string

const (
	// ParadigmProblemSolving — LeetCode, drills, grammar output. outcome
	// expresses how much help the learner needed.
	ParadigmProblemSolving Paradigm = "problem_solving"
	// ParadigmImmersive — reading, listening, literary analysis. outcome
	// expresses whether comprehension was self-sustained.
	ParadigmImmersive Paradigm = "immersive"
)

// MapOutcome resolves a caller-supplied semantic outcome (+ current session
// mode) into (paradigm, schema_outcome). The mode hint is only consulted for
// shared outcomes (incomplete, gave_up) whose paradigm cannot be inferred
// from the string alone. Returns an error if the semantic does not match any
// known pattern for the implied paradigm.
func MapOutcome(mode Mode, semantic string) (Paradigm, string, error) {
	// Accept raw enum values — paradigm is implied by the value except for
	// shared values where mode disambiguates.
	switch semantic {
	case "solved_independent", "solved_with_hint", "solved_after_solution":
		return ParadigmProblemSolving, semantic, nil
	case "completed", "completed_with_support":
		return ParadigmImmersive, semantic, nil
	case "incomplete", "gave_up":
		return paradigmForSharedOutcome(mode), semantic, nil
	}

	// Semantic shorthand — delegate to paradigm-scoped mapper by mode.
	switch mode {
	case ModePractice, ModeRetrieval, ModeMixed, ModeReview:
		out, err := mapProblemSolving(semantic)
		if err != nil {
			return "", "", err
		}
		return ParadigmProblemSolving, out, nil
	case ModeReading:
		out, err := mapImmersive(semantic)
		if err != nil {
			return "", "", err
		}
		return ParadigmImmersive, out, nil
	default:
		return "", "", fmt.Errorf("unknown session mode %q", mode)
	}
}

// paradigmForSharedOutcome picks a paradigm for outcomes that are legal
// under both (incomplete, gave_up). reading mode implies immersive; every
// other mode implies problem_solving. This is narrow mode→paradigm inference
// scoped only to shared outcomes; full paradigm inference from mode alone
// is unreliable and deliberately not attempted.
func paradigmForSharedOutcome(mode Mode) Paradigm {
	if mode == ModeReading {
		return ParadigmImmersive
	}
	return ParadigmProblemSolving
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
