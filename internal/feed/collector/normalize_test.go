// Copyright 2026 Koopa. All rights reserved.

package collector

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestNormalizeKeywords_Adversarial covers security and boundary inputs.
func TestNormalizeKeywords_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       []string
		wantLen   int  // -1 means don't check length
		wantEmpty bool // true = expect empty result
		wantNoDup bool // true = expect no duplicates
	}{
		{
			name:      "SQL injection keyword",
			raw:       []string{"'; DROP TABLE keywords; --"},
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "XSS keyword",
			raw:       []string{"<script>alert(1)</script>"},
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "null byte keyword skipped after trim",
			raw:       []string{"\x00"},
			wantLen:   1, // "\x00" is non-empty after TrimSpace
			wantNoDup: true,
		},
		{
			name:      "whitespace-only entries skipped",
			raw:       []string{"   ", "\t", "\n"},
			wantEmpty: true,
			wantNoDup: true,
		},
		{
			name: "large input — 10k keywords",
			raw: func() []string {
				kws := make([]string, 10000)
				for i := range kws {
					kws[i] = "keyword"
				}
				return kws
			}(),
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "emoji keywords deduplicated",
			raw:       []string{"🚀", "🚀", "go"},
			wantLen:   2,
			wantNoDup: true,
		},
		{
			name:      "mixed case dedup",
			raw:       []string{"GoLang", "GOLANG", "golang"},
			wantLen:   1,
			wantNoDup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeKeywords(tt.raw)

			if tt.wantEmpty && len(got) != 0 {
				t.Errorf("NormalizeKeywords(%v) = %v, want empty", tt.raw, got)
			}
			if tt.wantLen >= 0 && len(got) != tt.wantLen {
				t.Errorf("NormalizeKeywords(%v) len = %d, want %d; got %v", tt.raw, len(got), tt.wantLen, got)
			}
			if tt.wantNoDup {
				seen := make(map[string]int)
				for i, kw := range got {
					if prev, ok := seen[kw]; ok {
						t.Errorf("NormalizeKeywords: duplicate %q at index %d (first at %d)", kw, i, prev)
					}
					seen[kw] = i
				}
			}
		})
	}
}

// TestNormalizeKeywords_ReturnType verifies the return type contract:
// empty input returns empty slice (not nil), to allow safe range over result.
func TestNormalizeKeywords_ReturnType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []string
	}{
		{name: "nil input", raw: nil},
		{name: "empty slice", raw: []string{}},
		{name: "all whitespace", raw: []string{"  ", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeKeywords(tt.raw)
			// Must be non-nil (safe to range) and empty.
			if got == nil {
				t.Errorf("NormalizeKeywords(%v) = nil, want non-nil empty slice", tt.raw)
			}
			if diff := cmp.Diff([]string{}, got); diff != "" {
				t.Errorf("NormalizeKeywords(%v) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}
