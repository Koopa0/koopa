package hypothesis

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// ValidateResolveInput is the single source of truth for verify/invalidate
// input invariants — both the HTTP admin handler and the MCP
// track_hypothesis tool delegate to it. These tests cover every branch
// so drift between the two transports can only come from translation
// mistakes, not validation logic.

func TestValidateResolveInput_HappyPath(t *testing.T) {
	t.Parallel()

	attemptID := uuid.MustParse("22222222-2222-2222-2222-222222222222").String()
	observationID := uuid.MustParse("33333333-3333-3333-3333-333333333333").String()
	summary := "solved_independent on attempt #2, 8 min"

	tests := []struct {
		name    string
		attempt *string
		observ  *string
		summary *string
		want    ResolveParams
	}{
		{
			name:    "attempt only",
			attempt: &attemptID,
			want:    ResolveParams{AttemptID: mustParseUUID(t, attemptID)},
		},
		{
			name:   "observation only",
			observ: &observationID,
			want:   ResolveParams{ObservationID: mustParseUUID(t, observationID)},
		},
		{
			name:    "summary only",
			summary: &summary,
			want:    ResolveParams{ResolutionSummary: summary},
		},
		{
			name:    "all three",
			attempt: &attemptID,
			observ:  &observationID,
			summary: &summary,
			want: ResolveParams{
				AttemptID:         mustParseUUID(t, attemptID),
				ObservationID:     mustParseUUID(t, observationID),
				ResolutionSummary: summary,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateResolveInput(tt.attempt, tt.observ, tt.summary)
			if err != nil {
				t.Fatalf("ValidateResolveInput(%q) err = %v, want nil", tt.name, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ResolveParams mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateResolveInput_EvidenceRequired(t *testing.T) {
	t.Parallel()

	empty := ""
	whitespace := "   \t\n  "

	tests := []struct {
		name    string
		attempt *string
		observ  *string
		summary *string
	}{
		{name: "all nil"},
		{name: "all empty strings", attempt: &empty, observ: &empty, summary: &empty},
		{name: "whitespace-only summary", summary: &whitespace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateResolveInput(tt.attempt, tt.observ, tt.summary)
			if !errors.Is(err, ErrEvidenceRequired) {
				t.Errorf("ValidateResolveInput(%q) err = %v, want ErrEvidenceRequired", tt.name, err)
			}
		})
	}
}

func TestValidateResolveInput_InvalidEvidenceID(t *testing.T) {
	t.Parallel()

	bad := "not-a-uuid"
	summary := "also supplied"

	tests := []struct {
		name      string
		attempt   *string
		observ    *string
		summary   *string
		wantField string
	}{
		{
			name:      "malformed attempt",
			attempt:   &bad,
			wantField: "resolved_by_attempt_id",
		},
		{
			name:      "malformed observation",
			observ:    &bad,
			wantField: "resolved_by_observation_id",
		},
		{
			// UUID error MUST fire before the "at least one source" check
			// so malformed input surfaces loudly even when a summary is
			// also present.
			name:      "malformed attempt with valid summary",
			attempt:   &bad,
			summary:   &summary,
			wantField: "resolved_by_attempt_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateResolveInput(tt.attempt, tt.observ, tt.summary)
			fieldErr, ok := errors.AsType[*InvalidEvidenceIDError](err)
			if !ok {
				t.Fatalf("err = %v, want *InvalidEvidenceIDError", err)
			}
			if fieldErr.Field != tt.wantField {
				t.Errorf("field = %q, want %q", fieldErr.Field, tt.wantField)
			}
			// Sanity check: the inner uuid.Parse error MUST NOT be
			// reachable via Unwrap — we intentionally drop it at the
			// MCP boundary so "invalid UUID length: 3"-type internals
			// never reach the client.
			if errors.Unwrap(err) != nil {
				t.Errorf("InvalidEvidenceIDError.Unwrap() = %v, want nil (must not wrap uuid.Parse)", errors.Unwrap(err))
			}
		})
	}
}

func TestValidateResolveInput_SummaryTooLong(t *testing.T) {
	t.Parallel()

	oversize := strings.Repeat("a", MaxResolutionSummary+1)
	_, err := ValidateResolveInput(nil, nil, &oversize)
	if !errors.Is(err, ErrResolutionSummaryTooLong) {
		t.Errorf("err = %v, want ErrResolutionSummaryTooLong", err)
	}
}

func TestValidateResolveInput_ControlChars(t *testing.T) {
	t.Parallel()

	// Cases from .claude/rules/security.md: block C0 (0x00-0x1F) except
	// HT/LF/CR, block DEL (0x7F), block C1 (0x80-0x9F). Control code
	// points in the source MUST use \x / \u escapes (ST1018) so the
	// file itself stays ASCII-safe.
	tests := []struct {
		name    string
		summary string
		reject  bool
	}{
		{name: "NUL byte", summary: "hello\x00world", reject: true},
		{name: "BEL", summary: "hello\x07world", reject: true},
		{name: "ESC (terminal escape initiator)", summary: "\x1b[31mred", reject: true},
		{name: "DEL", summary: "hello\x7fworld", reject: true},
		{name: "C1 NEL (U+0085)", summary: "hello\u0085world", reject: true},
		{name: "C1 CSI (U+009B)", summary: "hello\u009bworld", reject: true},
		{name: "tab allowed", summary: "col1\tcol2", reject: false},
		{name: "newline allowed", summary: "line1\nline2", reject: false},
		{name: "CR allowed", summary: "line1\rline2", reject: false},
		{name: "plain ASCII allowed", summary: "solved cleanly", reject: false},
		{name: "non-ASCII letter allowed", summary: "解決しました", reject: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateResolveInput(nil, nil, &tt.summary)
			got := errors.Is(err, ErrResolutionSummaryInvalid)
			if got != tt.reject {
				t.Errorf("ValidateResolveInput(%q) rejected = %v, want %v (err=%v)",
					tt.name, got, tt.reject, err)
			}
		})
	}
}

func mustParseUUID(t *testing.T, s string) *uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", s, err)
	}
	return &u
}
