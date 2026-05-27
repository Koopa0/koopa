package mcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/build"
	"github.com/Koopa0/koopa/internal/stats"
)

// TestSystemStatusOutput_WrapperWireShape pins the MCP-side wrapper shape
// {scope, build, health?, last_agent_schedule_runs} for the system_status
// tool. The inner SystemHealthSnapshot is contract-tested in
// internal/stats/stats_test.go::TestSystemHealthSnapshotWireContract —
// THIS test deliberately does not re-pin those internals.
//
// Notes:
//   - `health` has `omitempty`: when nil, the key MUST be absent (not
//     present-with-null), so the wrapper can return a thin status
//     response without the full health snapshot.
//   - `build` is always present. We do NOT assert specific build values
//     (SHA / BuiltAt / Version are ldflag-stamped at link time and
//     differ between local builds and CI).
//   - `last_agent_schedule_runs` is always present — the field carries
//     observability for the external schedule runner; consumers rely on
//     the key being present whether or not any agent has ever run.
func TestSystemStatusOutput_WrapperWireShape(t *testing.T) {
	t.Parallel()

	ts := "2026-05-27T08:00:00Z"

	tests := []struct {
		name       string
		out        SystemStatusOutput
		wantHealth bool
	}{
		{
			name: "nil health — omitempty strips the key",
			out: SystemStatusOutput{
				Scope:                 "summary",
				Build:                 build.Info{SHA: "abc1234", BuiltAt: "2026-05-27T00:00:00Z", Version: "v0.0.0-dev"},
				Health:                nil,
				LastAgentScheduleRuns: map[string]*string{},
			},
			wantHealth: false,
		},
		{
			name: "populated health — key present, content delegated",
			out: SystemStatusOutput{
				Scope: "summary",
				Build: build.Info{SHA: "abc1234", BuiltAt: "2026-05-27T00:00:00Z", Version: "v0.0.0-dev"},
				Health: &stats.SystemHealthSnapshot{
					Feeds:     stats.FeedHealth{FailingFeeds: []stats.FailingFeed{}},
					Pipelines: stats.PipelineHealth{},
				},
				LastAgentScheduleRuns: map[string]*string{
					"hq":             &ts,
					"content-studio": nil,
				},
			},
			wantHealth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			for _, key := range []string{"scope", "build", "last_agent_schedule_runs"} {
				if _, ok := parsed[key]; !ok {
					t.Errorf("SystemStatusOutput missing required key %q", key)
				}
			}

			_, hasHealth := parsed["health"]
			if hasHealth != tt.wantHealth {
				t.Errorf("SystemStatusOutput has health key = %v, want %v (must honor omitempty)", hasHealth, tt.wantHealth)
			}

			// build must be a JSON object, not a primitive.
			// Do NOT assert on inner build field values — ldflag-stamped
			// and varies by build environment.
			if rawBuild, ok := parsed["build"]; ok {
				if string(rawBuild) == "null" {
					t.Errorf("SystemStatusOutput[build] = null, want JSON object")
				}
				if len(rawBuild) > 0 && rawBuild[0] != '{' {
					t.Errorf("SystemStatusOutput[build] = %s, want a JSON object", rawBuild)
				}
			}
		})
	}
}

// TestSystemStatusOutput_LastAgentScheduleRunsValues pins the value shape of
// the last_agent_schedule_runs map: each entry serializes to either an
// RFC3339 string or JSON null. The map is the integration point between
// koopa and external Cowork/Desktop schedule observability, so the
// null-vs-string contract is load-bearing for consumers.
func TestSystemStatusOutput_LastAgentScheduleRunsValues(t *testing.T) {
	t.Parallel()

	ts := "2026-05-27T08:00:00Z"
	out := SystemStatusOutput{
		Scope: "summary",
		Build: build.Info{SHA: "abc1234", BuiltAt: "2026-05-27T00:00:00Z", Version: "v0.0.0-dev"},
		LastAgentScheduleRuns: map[string]*string{
			"hq":             &ts,
			"content-studio": nil,
		},
	}

	parsed := marshalToKeyMap(t, out)

	raw, ok := parsed["last_agent_schedule_runs"]
	if !ok {
		t.Fatal("SystemStatusOutput missing last_agent_schedule_runs key")
	}

	var got map[string]*string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decoding last_agent_schedule_runs: %v", err)
	}

	gotHQ, ok := got["hq"]
	if !ok || gotHQ == nil || *gotHQ != ts {
		t.Errorf("last_agent_schedule_runs[hq] = %v, want %q", gotHQ, ts)
	}
	gotCS, ok := got["content-studio"]
	if !ok || gotCS != nil {
		t.Errorf("last_agent_schedule_runs[content-studio] = %v, want JSON null (nil pointer)", gotCS)
	}

	// Sanity-check the raw bytes: content-studio must serialize as null,
	// not the string "null", and not be omitted.
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("decoding raw last_agent_schedule_runs: %v", err)
	}
	if string(rawMap["content-studio"]) != "null" {
		t.Errorf("last_agent_schedule_runs[content-studio] raw = %s, want literal null",
			string(rawMap["content-studio"]))
	}
}

// TestMergeAgentScheduleRuns covers the pure helper that produces the
// last_agent_schedule_runs wire map. Behaviour pinned:
//   - Every expected agent appears in the result, even with no observation.
//   - An observed agent overlays its timestamp in RFC3339 (UTC).
//   - Multiple observations for the same agent reduce to one entry
//     (caller-side dedup) — the helper trusts its input contract that
//     observed is already aggregated upstream by the SQL query.
//   - Observed-but-not-expected agents (registry drift) are kept so the
//     audit log is honest.
//   - A nil expected slice still produces a usable (non-nil) map.
func TestMergeAgentScheduleRuns(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, time.May, 27, 8, 0, 0, 0, time.UTC)
	whenStr := "2026-05-27T08:00:00Z"

	whenLater := time.Date(2026, time.May, 27, 9, 0, 0, 0, time.UTC)
	whenLaterStr := "2026-05-27T09:00:00Z"

	tests := []struct {
		name     string
		expected []agent.Name
		observed map[string]time.Time
		want     map[string]*string
	}{
		{
			name:     "expected agents only, none observed — every entry is nil",
			expected: []agent.Name{"hq", "content-studio"},
			observed: map[string]time.Time{},
			want: map[string]*string{
				"hq":             nil,
				"content-studio": nil,
			},
		},
		{
			name:     "expected agent observed — timestamp overlays nil",
			expected: []agent.Name{"hq", "content-studio"},
			observed: map[string]time.Time{
				"hq": when,
			},
			want: map[string]*string{
				"hq":             &whenStr,
				"content-studio": nil,
			},
		},
		{
			name:     "non-UTC observed time is normalized to UTC RFC3339",
			expected: []agent.Name{"hq"},
			observed: map[string]time.Time{
				// 2026-05-27T16:00:00+08:00 == 2026-05-27T08:00:00Z
				"hq": when.In(time.FixedZone("CST", 8*60*60)),
			},
			want: map[string]*string{
				"hq": &whenStr,
			},
		},
		{
			name:     "observed agent not in expected — included for drift visibility",
			expected: []agent.Name{"hq"},
			observed: map[string]time.Time{
				"hq":            when,
				"retired-agent": whenLater,
			},
			want: map[string]*string{
				"hq":            &whenStr,
				"retired-agent": &whenLaterStr,
			},
		},
		{
			name:     "nil expected slice — still produces map from observed",
			expected: nil,
			observed: map[string]time.Time{
				"hq": when,
			},
			want: map[string]*string{
				"hq": &whenStr,
			},
		},
		{
			name:     "fully empty inputs — empty non-nil map",
			expected: nil,
			observed: nil,
			want:     map[string]*string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mergeAgentScheduleRuns(tt.expected, tt.observed)
			if got == nil {
				t.Fatal("mergeAgentScheduleRuns() returned nil map, want non-nil (consumers rely on the key being present)")
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mergeAgentScheduleRuns() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestScheduledAgents_RegistryFilter pins the registry → expected-set
// projection. Behaviour pinned:
//   - A nil registry yields a nil slice (no panic).
//   - Only agents whose Schedule.IsZero() == false are returned.
//   - The output is deterministic (Registry.All sorts by name).
func TestScheduledAgents_RegistryFilter(t *testing.T) {
	t.Parallel()

	if got := scheduledAgents(nil); got != nil {
		t.Errorf("scheduledAgents(nil) = %v, want nil", got)
	}

	reg := agent.NewRegistry([]agent.Agent{
		{
			Name:     "alpha",
			Platform: "claude-cowork",
			Schedule: agent.Schedule{
				Name:    "morning",
				Trigger: agent.TriggerCron,
				Expr:    "0 8 * * *",
			},
		},
		{
			Name:     "bravo",
			Platform: "claude-cowork",
			// no Schedule — must be filtered out
		},
		{
			Name:     "charlie",
			Platform: "claude-cowork",
			Schedule: agent.Schedule{
				Name:    "weekly",
				Trigger: agent.TriggerCron,
				Expr:    "0 9 * * 1",
			},
		},
	})

	got := scheduledAgents(reg)
	want := []agent.Name{"alpha", "charlie"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("scheduledAgents() mismatch (-want +got):\n%s", diff)
	}
}
