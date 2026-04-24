package feed

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestValidSchedule(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "hourly", input: "hourly", want: true},
		{name: "daily", input: "daily", want: true},
		{name: "weekly", input: "weekly", want: true},
		{name: "biweekly", input: "biweekly", want: true},
		{name: "monthly", input: "monthly", want: true},
		{name: "legacy hourly_4 rejected", input: "hourly_4", want: false},
		{name: "unknown value", input: "yearly", want: false},
		{name: "empty", input: "", want: false},
		{name: "case sensitive", input: "Daily", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidSchedule(tt.input)
			if got != tt.want {
				t.Errorf("ValidSchedule(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseTopicIDs exercises the handler-side topic_id validator. The three
// states that UpdateFeed relies on — nil input, non-nil empty input, and
// populated input — are each covered to lock the nil-vs-empty contract
// documented on UpdateParams.TopicIDs.
func TestParseTopicIDs(t *testing.T) {
	good := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	good2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	tests := []struct {
		name    string
		input   []string
		wantIDs []uuid.UUID
		wantErr error
	}{
		{
			name:    "nil input preserves nil (no change)",
			input:   nil,
			wantIDs: nil,
		},
		{
			name:    "empty slice preserves non-nil empty (clear)",
			input:   []string{},
			wantIDs: []uuid.UUID{},
		},
		{
			name:    "single valid uuid",
			input:   []string{good.String()},
			wantIDs: []uuid.UUID{good},
		},
		{
			name:    "multiple valid uuids",
			input:   []string{good.String(), good2.String()},
			wantIDs: []uuid.UUID{good, good2},
		},
		{
			name:    "invalid uuid rejected",
			input:   []string{"not-a-uuid"},
			wantIDs: nil,
			wantErr: ErrInvalidTopicID,
		},
		{
			name:    "over cap rejected",
			input:   overCapStrings(maxTopicIDs + 1),
			wantIDs: nil,
			wantErr: ErrTooManyTopicIDs,
		},
		{
			name:    "exactly at cap accepted",
			input:   overCapStrings(maxTopicIDs),
			wantIDs: overCapUUIDs(maxTopicIDs),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIDs, err := parseTopicIDs(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("parseTopicIDs err = %v, want %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("parseTopicIDs ids mismatch (-want +got):\n%s", diff)
			}
			// Explicit nil-vs-empty guard: a nil input must yield a nil
			// slice and a non-nil empty input must yield a non-nil
			// empty slice. cmp.Diff treats these as equal, so check
			// the bit directly.
			if tt.wantErr == nil && (tt.input == nil) != (gotIDs == nil) {
				t.Errorf("parseTopicIDs nil-ness mismatch: input nil=%v, output nil=%v",
					tt.input == nil, gotIDs == nil)
			}
		})
	}
}

// overCapStrings returns n deterministic uuid strings. Kept in the test file
// because it's only used here.
func overCapStrings(n int) []string {
	out := make([]string, n)
	for i := range n {
		// Build a valid uuid whose last hex segment encodes i; any two
		// differ so bulk validation treats them as distinct rows.
		out[i] = uuid.NewSHA1(uuid.Nil, []byte{byte(i >> 8), byte(i)}).String()
	}
	return out
}

func overCapUUIDs(n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range n {
		out[i] = uuid.NewSHA1(uuid.Nil, []byte{byte(i >> 8), byte(i)})
	}
	return out
}
