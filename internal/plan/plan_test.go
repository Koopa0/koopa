package plan

import (
	"errors"
	"testing"
)

func TestValidatePhase(t *testing.T) {
	valid := []struct {
		name  string
		phase string
	}{
		{"digits first", "1-arrays"},
		{"digits first alt", "2-trees"},
		{"alpha first", "phase-1"},
		{"multi segment", "phase-2-trees"},
		{"single word", "easy"},
		{"two chars", "dp"},
		{"single char", "a"},
		{"single digit", "1"},
	}

	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			if err := ValidatePhase(tc.phase); err != nil {
				t.Errorf("ValidatePhase(%q) = %v, want nil", tc.phase, err)
			}
		})
	}

	invalid := []struct {
		name  string
		phase string
	}{
		{"empty", ""},
		{"uppercase", "Phase-1"},
		{"space", "phase 1"},
		{"underscore", "phase_1"},
		{"dot", "phase.1"},
		{"leading hyphen", "-phase"},
		{"trailing hyphen", "phase-"},
		{"double hyphen", "phase--1"},
	}

	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			if err := ValidatePhase(tc.phase); err == nil {
				t.Errorf("ValidatePhase(%q) = nil, want error", tc.phase)
			}
		})
	}
}

func TestStatusConstants(t *testing.T) {
	tests := []struct {
		got  Status
		want string
	}{
		{StatusDraft, "draft"},
		{StatusActive, "active"},
		{StatusCompleted, "completed"},
		{StatusPaused, "paused"},
		{StatusAbandoned, "abandoned"},
	}

	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("Status constant = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestItemStatusConstants(t *testing.T) {
	tests := []struct {
		got  ItemStatus
		want string
	}{
		{ItemPlanned, "planned"},
		{ItemCompleted, "completed"},
		{ItemSkipped, "skipped"},
		{ItemSubstituted, "substituted"},
	}

	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("ItemStatus constant = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestSentinelErrors(t *testing.T) {
	if !errors.Is(ErrNotFound, ErrNotFound) {
		t.Fatal("ErrNotFound must match itself via errors.Is")
	}
	if !errors.Is(ErrConflict, ErrConflict) {
		t.Fatal("ErrConflict must match itself via errors.Is")
	}
	if errors.Is(ErrNotFound, ErrConflict) {
		t.Fatal("ErrNotFound must not match ErrConflict")
	}
	if errors.Is(ErrConflict, ErrNotFound) {
		t.Fatal("ErrConflict must not match ErrNotFound")
	}
}
