package reconcile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// --- diff ---

func TestDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		source       []string
		target       []string
		wantMissing  []string
		wantOrphaned []string
	}{
		{
			name:         "both empty",
			source:       nil,
			target:       nil,
			wantMissing:  nil,
			wantOrphaned: nil,
		},
		{
			name:         "perfect sync",
			source:       []string{"a", "b", "c"},
			target:       []string{"a", "b", "c"},
			wantMissing:  nil,
			wantOrphaned: nil,
		},
		{
			name:        "missing in target",
			source:      []string{"a", "b", "c"},
			target:      []string{"a"},
			wantMissing: []string{"b", "c"},
		},
		{
			name:         "orphaned in target",
			source:       []string{"a"},
			target:       []string{"a", "b", "c"},
			wantOrphaned: []string{"b", "c"},
		},
		{
			name:         "missing and orphaned",
			source:       []string{"a", "b"},
			target:       []string{"b", "c"},
			wantMissing:  []string{"a"},
			wantOrphaned: []string{"c"},
		},
		{
			name:        "source non-empty, target empty",
			source:      []string{"a", "b"},
			target:      nil,
			wantMissing: []string{"a", "b"},
		},
		{
			name:         "source empty, target non-empty",
			source:       nil,
			target:       []string{"a", "b"},
			wantOrphaned: []string{"a", "b"},
		},
		{
			name:         "single element match",
			source:       []string{"x"},
			target:       []string{"x"},
			wantMissing:  nil,
			wantOrphaned: nil,
		},
	}

	sortStrings := cmpopts.SortSlices(func(a, b string) bool { return a < b })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing, gotOrphaned := diff(tt.source, tt.target)

			if diff := cmp.Diff(tt.wantMissing, gotMissing, sortStrings, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("missing mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantOrphaned, gotOrphaned, sortStrings, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("orphaned mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- Report.HasIssues ---

func TestReportHasIssues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    Report
		want bool
	}{
		{
			name: "empty report has no issues",
			r:    Report{},
			want: false,
		},
		{
			name: "obsidian missing triggers issue",
			r:    Report{ObsidianMissing: []string{"slug-a"}},
			want: true,
		},
		{
			name: "obsidian orphaned triggers issue",
			r:    Report{ObsidianOrphaned: []string{"slug-b"}},
			want: true,
		},
		{
			name: "projects missing triggers issue",
			r:    Report{ProjectsMissing: []string{"page-1"}},
			want: true,
		},
		{
			name: "projects orphaned triggers issue",
			r:    Report{ProjectsOrphaned: []string{"page-2"}},
			want: true,
		},
		{
			name: "goals missing triggers issue",
			r:    Report{GoalsMissing: []string{"goal-1"}},
			want: true,
		},
		{
			name: "goals orphaned triggers issue",
			r:    Report{GoalsOrphaned: []string{"goal-2"}},
			want: true,
		},
		{
			name: "all fields populated is an issue",
			r: Report{
				ObsidianMissing:  []string{"a"},
				ObsidianOrphaned: []string{"b"},
				ProjectsMissing:  []string{"c"},
				ProjectsOrphaned: []string{"d"},
				GoalsMissing:     []string{"e"},
				GoalsOrphaned:    []string{"f"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.r.HasIssues()
			if got != tt.want {
				t.Errorf("HasIssues() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- formatReport ---

func TestFormatReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		r           Report
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "empty report has header only",
			r:           Report{},
			wantContain: []string{"[Reconciliation Report]"},
			wantAbsent:  []string{"GitHub", "Obsidian:", "Projects:", "Goals:"},
		},
		{
			name:        "obsidian missing shows plus lines",
			r:           Report{ObsidianMissing: []string{"post-a", "post-b"}},
			wantContain: []string{"Obsidian:", "2 files in GitHub but not in DB", "+ post-a", "+ post-b"},
		},
		{
			name:        "obsidian orphaned shows minus lines",
			r:           Report{ObsidianOrphaned: []string{"old-post"}},
			wantContain: []string{"Obsidian:", "1 records in DB but not in GitHub", "- old-post"},
		},
		{
			name:        "projects missing",
			r:           Report{ProjectsMissing: []string{"proj-id-1"}},
			wantContain: []string{"Projects:", "1 in Notion but not in DB", "+ proj-id-1"},
		},
		{
			name:        "goals orphaned",
			r:           Report{GoalsOrphaned: []string{"goal-id-1"}},
			wantContain: []string{"Goals:", "1 in DB but not in Notion", "- goal-id-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatReport(&tt.r)
			for _, sub := range tt.wantContain {
				if !strings.Contains(got, sub) {
					t.Errorf("formatReport() output missing %q\nfull output:\n%s", sub, got)
				}
			}
			for _, sub := range tt.wantAbsent {
				if strings.Contains(got, sub) {
					t.Errorf("formatReport() output should not contain %q\nfull output:\n%s", sub, got)
				}
			}
		})
	}
}

// --- diff: adversarial + boundary extensions ---

func TestDiff_Adversarial(t *testing.T) {
	t.Parallel()

	sortStrings := cmpopts.SortSlices(func(a, b string) bool { return a < b })

	tests := []struct {
		name         string
		source       []string
		target       []string
		wantMissing  []string
		wantOrphaned []string
	}{
		{
			name:         "duplicates in source",
			source:       []string{"a", "a", "b"},
			target:       []string{"b"},
			wantMissing:  []string{"a", "a"}, // each "a" in source is checked against target
			wantOrphaned: nil,
		},
		{
			name:         "duplicates in target",
			source:       []string{"a"},
			target:       []string{"a", "a", "b"},
			wantOrphaned: []string{"b"}, // deduplicated by targetSet
		},
		{
			name:   "large symmetric diff",
			source: generateStrings("src-", 100),
			target: generateStrings("tgt-", 100),
			// all source items are missing from target, all target items orphaned
			wantMissing:  generateStrings("src-", 100),
			wantOrphaned: generateStrings("tgt-", 100),
		},
		{
			name:   "large perfect sync",
			source: generateStrings("item-", 500),
			target: generateStrings("item-", 500),
		},
		{
			name:         "unicode strings",
			source:       []string{"日本語", "中文", "한국어"},
			target:       []string{"中文", "Русский"},
			wantMissing:  []string{"日本語", "한국어"},
			wantOrphaned: []string{"Русский"},
		},
		{
			name:         "empty strings as elements",
			source:       []string{"", "a"},
			target:       []string{"a", ""},
			wantMissing:  nil,
			wantOrphaned: nil,
		},
		{
			name:         "whitespace-only strings",
			source:       []string{" ", "\t", "\n"},
			target:       []string{" "},
			wantMissing:  []string{"\t", "\n"},
			wantOrphaned: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing, gotOrphaned := diff(tt.source, tt.target)

			if d := cmp.Diff(tt.wantMissing, gotMissing, sortStrings, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("missing mismatch (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.wantOrphaned, gotOrphaned, sortStrings, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("orphaned mismatch (-want +got):\n%s", d)
			}
		})
	}
}

// --- formatReport: boundary extensions ---

func TestFormatReport_Boundary(t *testing.T) {
	t.Parallel()

	t.Run("all six sections populated", func(t *testing.T) {
		t.Parallel()
		r := Report{
			ObsidianMissing:  []string{"a"},
			ObsidianOrphaned: []string{"b"},
			ProjectsMissing:  []string{"c"},
			ProjectsOrphaned: []string{"d"},
			GoalsMissing:     []string{"e"},
			GoalsOrphaned:    []string{"f"},
		}
		got := formatReport(&r)
		sections := []string{"Obsidian:", "Projects:", "Goals:"}
		for _, s := range sections {
			if count := strings.Count(got, s); count < 1 {
				t.Errorf("formatReport() missing section %q", s)
			}
		}
		if !strings.Contains(got, "+ a") || !strings.Contains(got, "- b") {
			t.Errorf("formatReport() missing +/- markers\noutput:\n%s", got)
		}
	})

	t.Run("large report does not truncate", func(t *testing.T) {
		t.Parallel()
		r := Report{
			ObsidianMissing: generateStrings("slug-", 200),
		}
		got := formatReport(&r)
		if !strings.Contains(got, "200 files in GitHub") {
			t.Errorf("formatReport() large report: expected 200 count in output\n%s", got[:200])
		}
		// verify last item is present
		if !strings.Contains(got, "+ slug-199") {
			t.Errorf("formatReport() large report truncated, missing last item")
		}
	})

	t.Run("unicode in report items", func(t *testing.T) {
		t.Parallel()
		r := Report{
			GoalsMissing: []string{"學習-Go-泛型"},
		}
		got := formatReport(&r)
		if !strings.Contains(got, "學習-Go-泛型") {
			t.Errorf("formatReport() unicode item not in output\n%s", got)
		}
	})
}

// --- HasIssues: boundary (zero-value Report fields) ---

func TestReportHasIssues_EmptySlices(t *testing.T) {
	t.Parallel()

	// empty (non-nil) slices should NOT count as issues
	r := Report{
		ObsidianMissing:  []string{},
		ObsidianOrphaned: []string{},
		ProjectsMissing:  []string{},
		ProjectsOrphaned: []string{},
		GoalsMissing:     []string{},
		GoalsOrphaned:    []string{},
	}
	if r.HasIssues() {
		t.Error("HasIssues() = true for Report with empty (non-nil) slices, want false")
	}
}

// --- helpers ---

func generateStrings(prefix string, n int) []string {
	s := make([]string, n)
	for i := range n {
		s[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return s
}
