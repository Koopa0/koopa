package hypothesis

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// MaxResolutionSummary caps the free-text resolution_summary field at 2 KB.
// The same cap is enforced by every transport (HTTP admin handler and MCP
// track_hypothesis) via ValidateResolveInput so oversize payloads never
// reach the query layer regardless of how the request arrived.
const MaxResolutionSummary = 2 * 1024

// Sentinel errors returned by ValidateResolveInput.
//
// These are distinct from the store-layer sentinels (ErrNotFound,
// ErrEvidenceNotFound, etc.) because they describe client input problems
// that are detected before any DB round-trip. ErrEvidenceRequired is
// shared with the store sentinel so a single ErrMap entry covers both
// the inline-validation path and the last-resort schema CHECK.
var (
	// ErrResolutionSummaryTooLong indicates resolution_summary exceeded
	// MaxResolutionSummary bytes.
	ErrResolutionSummaryTooLong = errors.New("hypothesis: resolution_summary too large")

	// ErrResolutionSummaryInvalid indicates resolution_summary contains
	// ASCII C0/C1 control characters or DEL. Blocking these at the
	// validator layer prevents terminal-escape and bidi-override tricks
	// from reaching storage or downstream renderers.
	ErrResolutionSummaryInvalid = errors.New("hypothesis: resolution_summary contains control characters")
)

// InvalidEvidenceIDError reports which UUID field failed to parse. The
// transport layer uses Field to format a client-facing message without
// leaking uuid.Parse's "invalid UUID length: 3" internals.
//
// Callers should match with errors.As (or errors.AsType) and format the
// response themselves — the Error() string here is deliberately terse.
type InvalidEvidenceIDError struct {
	Field string
}

func (e *InvalidEvidenceIDError) Error() string {
	return "invalid " + e.Field
}

// ValidateResolveInput enforces the invariants required for a transition
// to verified or invalidated:
//
//   - at least one of attemptID, observationID, or a non-blank summary
//     is present (after trimming whitespace);
//   - attemptID and observationID parse as UUIDs when supplied;
//   - summary is ≤ MaxResolutionSummary bytes and contains no C0/C1
//     control characters.
//
// Validation order is load-bearing and mirrors the HTTP and MCP handlers
// it replaces: UUIDs are parsed BEFORE the "at least one source" check so
// a malformed UUID surfaces first even if the caller also supplied a
// summary. This keeps client errors loud instead of silently succeeding
// with a partial payload.
//
// Summary trimming matches the DB CHECK (btrim(resolution_summary) <> ”)
// — a whitespace-only summary is treated as "not supplied" for the "at
// least one source" check, but the length cap still applies to the raw
// byte count because an oversize blob of whitespace is still an oversize
// payload.
func ValidateResolveInput(attemptID, observationID, summary *string) (ResolveParams, error) {
	parsedAttempt, err := parseEvidenceUUID(attemptID, "resolved_by_attempt_id")
	if err != nil {
		return ResolveParams{}, err
	}
	parsedObservation, err := parseEvidenceUUID(observationID, "resolved_by_observation_id")
	if err != nil {
		return ResolveParams{}, err
	}

	summaryStr := ""
	if summary != nil {
		summaryStr = *summary
	}
	if len(summaryStr) > MaxResolutionSummary {
		return ResolveParams{}, fmt.Errorf("%w (max %d bytes)", ErrResolutionSummaryTooLong, MaxResolutionSummary)
	}
	if containsControlChars(summaryStr) {
		return ResolveParams{}, ErrResolutionSummaryInvalid
	}

	if parsedAttempt == nil && parsedObservation == nil && strings.TrimSpace(summaryStr) == "" {
		return ResolveParams{}, ErrEvidenceRequired
	}

	return ResolveParams{
		AttemptID:         parsedAttempt,
		ObservationID:     parsedObservation,
		ResolutionSummary: summaryStr,
	}, nil
}

// parseEvidenceUUID parses an optional UUID field, returning (nil, nil)
// for absent or empty input. An invalid UUID yields *InvalidEvidenceIDError
// naming the field; the underlying uuid.Parse error is intentionally NOT
// wrapped so its internal shape ("invalid UUID length: 3" etc.) never
// reaches the client.
func parseEvidenceUUID(raw *string, field string) (*uuid.UUID, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(*raw)
	if err != nil {
		return nil, &InvalidEvidenceIDError{Field: field}
	}
	return &parsed, nil
}

// containsControlChars reports whether s contains any ASCII C0 control
// (0x00-0x1F), DEL (0x7F), or Unicode C1 control (0x80-0x9F), EXCEPT
// for HT (0x09), LF (0x0A), and CR (0x0D). The three whitespace
// controls are exempt because resolution_summary is free-text prose
// where line breaks and tabs are legitimate formatting — unlike slugs
// or hostnames (internal/tag/tag.go, internal/feed/collector/ratelimit.go)
// which reject all C0.
//
// The security intent matches .claude/rules/security.md: block
// 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F, 0x80-0x9F — the invisible
// controls and escape-sequence initiators used in terminal-escape and
// bidi-override attacks — while still permitting the whitespace that
// strings.TrimSpace and PostgreSQL btrim would treat as trimmable.
func containsControlChars(s string) bool {
	for _, r := range s {
		switch {
		case r == 0x09, r == 0x0a, r == 0x0d:
			// HT, LF, CR — legitimate whitespace in free-text.
			continue
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return true
		}
	}
	return false
}
