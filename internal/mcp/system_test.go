package mcp

import (
	"testing"

	"github.com/Koopa0/koopa/internal/build"
	"github.com/Koopa0/koopa/internal/stats"
)

// TestSystemStatusOutput_WrapperWireShape pins the MCP-side wrapper shape
// {scope, build, health?} for the system_status tool. The inner
// SystemHealthSnapshot is contract-tested in
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
func TestSystemStatusOutput_WrapperWireShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		out        SystemStatusOutput
		wantHealth bool
	}{
		{
			name: "nil health — omitempty strips the key",
			out: SystemStatusOutput{
				Scope:  "summary",
				Build:  build.Info{SHA: "abc1234", BuiltAt: "2026-05-27T00:00:00Z", Version: "v0.0.0-dev"},
				Health: nil,
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
			},
			wantHealth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			for _, key := range []string{"scope", "build"} {
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
