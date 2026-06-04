// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa/internal/mcp/ops"
	"github.com/Koopa0/koopa/internal/research"
)

// TestReportToolSurface pins the agent-facing vocabulary for the report lane:
// assign_research and create_report are present, and NO human-authority report
// action (trust promotion / acceptance / formal revision) is exposed via MCP.
func TestReportToolSurface(t *testing.T) {
	names := make(map[string]bool)
	for _, m := range ops.All() {
		names[m.Name] = true
	}
	for _, want := range []string{"assign_research", "create_report"} {
		if !names[want] {
			t.Errorf("ops.All() is missing report-lane tool %q", want)
		}
	}
	// Trust promotion, acceptance, and formal revision are human/admin verdicts.
	// None of them may surface as an agent-facing MCP tool.
	for _, forbidden := range []string{
		"set_report_trust", "promote_report", "trust_report",
		"approve_report", "accept_report", "review_report", "revise_report",
		"request_report_revision",
	} {
		if names[forbidden] {
			t.Errorf("ops.All() exposes human-authority report tool %q; trust/acceptance/revision must stay human/admin, not MCP", forbidden)
		}
	}
}

func TestReportWeight(t *testing.T) {
	trusted := reportWeight(string(research.TrustTrusted))
	low := reportWeight(string(research.TrustLow))
	if trusted <= low {
		t.Errorf("reportWeight(trusted)=%v must exceed reportWeight(low_trust)=%v", trusted, low)
	}
	if low <= 0 || trusted > 1.0 {
		t.Errorf("report weights must lie in (0,1]: trusted=%v low=%v", trusted, low)
	}
	if got := reportWeight("unknown"); got != low {
		t.Errorf("reportWeight(unknown)=%v, want low_trust weight %v (unknown trust defaults to low)", got, low)
	}
}

// TestMergeByRelevance_ReportsDownrankedBelowNotes pins the core ranking
// invariant: a low-trust report, even when newer, ranks below a note at the
// same branch position — agent sources never drown out personal notes — yet
// the report stays present (visibility is never gated by trust).
func TestMergeByRelevance_ReportsDownrankedBelowNotes(t *testing.T) {
	noteRes := SearchKnowledgeResult{ID: testID(1).String(), SourceType: SourceTypeNote, CreatedAt: "2026-01-01T00:00:00Z"}
	lowReport := SearchKnowledgeResult{ID: testID(2).String(), SourceType: SourceTypeReport, TrustStatus: "low_trust", CreatedAt: "2026-06-01T00:00:00Z"}

	got := mergeByRelevance(nil, []SearchKnowledgeResult{noteRes}, []SearchKnowledgeResult{lowReport}, 20)
	if len(got) != 2 {
		t.Fatalf("merge returned %d results, want 2 (both visible)", len(got))
	}
	if got[0].ID != noteRes.ID {
		t.Errorf("got[0] = (source=%q id=%q); want the note first — reports must not outrank notes", got[0].SourceType, got[0].ID)
	}
	if got[1].ID != lowReport.ID {
		t.Errorf("got[1].id = %q; want the low-trust report present but second (downranked, not hidden)", got[1].ID)
	}
}

func TestFilterReportResults(t *testing.T) {
	reports := []research.Report{
		{ID: testID(7), Title: "kept", Body: "body text", TrustStatus: research.TrustLow, CreatedAt: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)},
	}
	got := filterReportResults(reports, nil, nil)
	if len(got) != 1 {
		t.Fatalf("filterReportResults returned %d results, want 1", len(got))
	}
	want := SearchKnowledgeResult{
		ID:          testID(7).String(),
		SourceType:  SourceTypeReport,
		Title:       "kept",
		Excerpt:     "body text",
		TrustStatus: "low_trust",
		CreatedAt:   "2026-06-01T12:00:00Z",
	}
	if diff := cmp.Diff(want, got[0]); diff != "" {
		t.Errorf("filterReportResults mismatch (-want +got):\n%s", diff)
	}
}
