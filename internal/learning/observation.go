package learning

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// normalizeConfidenceFilter validates and defaults the dashboard's
// confidence filter. Empty becomes "high"; "high" and "all" pass through;
// anything else is rejected. Without this guard a typo would silently
// fall through the SQL predicate `(@cf = 'all' OR confidence = 'high')`
// and produce a high-only result, masking the bug from the caller.
func normalizeConfidenceFilter(v string) (string, error) {
	switch v {
	case "", "high":
		return "high", nil
	case "all":
		return "all", nil
	default:
		return "", fmt.Errorf("%w: confidence_filter must be \"high\" or \"all\", got %q", ErrInvalidInput, v)
	}
}

// normalizeObservationConfidence validates and defaults the per-observation
// confidence label. Empty becomes "high"; "high" and "low" pass through;
// anything else is rejected with ErrInvalidInput. Symmetric with
// normalizeConfidenceFilter — without this the DB CHECK constraint would
// catch typos as a 23514 violation deep inside the INSERT, instead of as
// a clean validation error at the boundary.
func normalizeObservationConfidence(v string) (string, error) {
	switch v {
	case "", "high":
		return "high", nil
	case "low":
		return "low", nil
	default:
		return "", fmt.Errorf("%w: observation confidence must be \"high\" or \"low\", got %q", ErrInvalidInput, v)
	}
}

// normalizeSignal validates the observation signal type. Valid values are
// "weakness", "improvement", and "mastery" — matching the DB CHECK
// constraint on attempt_observations.signal_type. Rejects typos and
// case-mismatches at the Go boundary with a descriptive error.
func normalizeSignal(v string) (string, error) {
	switch v {
	case "weakness", "improvement", "mastery":
		return v, nil
	default:
		return "", fmt.Errorf("%w: signal must be \"weakness\", \"improvement\", or \"mastery\", got %q", ErrInvalidInput, v)
	}
}

// validateSeverity enforces two rules from the DB schema:
//  1. severity values must be "minor", "moderate", or "critical"
//  2. severity is only allowed when signal is "weakness" (chk_severity_weakness_only)
//
// Returns nil when severity is nil (always valid for any signal).
func validateSeverity(signal string, severity *string) error {
	if severity == nil {
		return nil
	}
	switch *severity {
	case "minor", "moderate", "critical":
		// valid value — check signal constraint
	default:
		return fmt.Errorf("%w: severity must be \"minor\", \"moderate\", or \"critical\", got %q", ErrInvalidInput, *severity)
	}
	if signal != "weakness" {
		return fmt.Errorf("%w: severity %q not allowed for signal %q (weakness only)", ErrInvalidInput, *severity, signal)
	}
	return nil
}

// RecordObservation creates an observation linking an attempt to a concept.
// confidence is "high" (default — directly evidenced) or "low" (inferred).
// Both persist; the dashboard filters at read time. Invalid values are
// rejected at the boundary so a typo cannot reach the DB CHECK as a
// 23514 violation.
func (s *Store) RecordObservation(ctx context.Context, attemptID, conceptID uuid.UUID, signalType, category string, severity, detail *string, confidence string) (*Observation, error) {
	normalized, err := normalizeObservationConfidence(confidence)
	if err != nil {
		return nil, err
	}
	signal, err := normalizeSignal(signalType)
	if err != nil {
		return nil, err
	}
	if err = validateSeverity(signal, severity); err != nil { //nolint:gocritic // := triggers govet shadow; = reuse is intentional
		return nil, err
	}
	row, err := s.q.CreateObservation(ctx, db.CreateObservationParams{
		AttemptID:  attemptID,
		ConceptID:  conceptID,
		SignalType: signal,
		Category:   category,
		Severity:   severity,
		Detail:     detail,
		Confidence: normalized,
	})
	if err != nil {
		return nil, fmt.Errorf("creating observation: %w", err)
	}
	return &Observation{
		ID:         row.ID,
		AttemptID:  row.AttemptID,
		ConceptID:  row.ConceptID,
		SignalType: row.SignalType,
		Category:   row.Category,
		Severity:   row.Severity,
		Detail:     row.Detail,
		Confidence: row.Confidence,
	}, nil
}
