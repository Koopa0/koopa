package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Koopa0/koopa/internal/agent"
)

// withCallerAs returns a context where the caller identity has been
// supplied explicitly via `as` — the same shape extractCallerIdentity
// produces from a real MCP request.
func withCallerAs(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, callerKey{}, name)
}

func TestRequireExplicitHuman(t *testing.T) {
	s := newTestServer()

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr string
	}{
		{
			name:    "no explicit as — refuse default",
			ctx:     t.Context(),
			wantErr: "refusing without explicit `as` field",
		},
		{
			name:    "explicit non-human caller",
			ctx:     withCallerAs(t.Context(), "hq"),
			wantErr: `caller "hq" is not authorized (human-only)`,
		},
		{
			name:    "explicit unregistered caller",
			ctx:     withCallerAs(t.Context(), "ghost"),
			wantErr: `caller "ghost" is not registered`,
		},
		{
			// CF-02: even when explicit, the zero-privilege fallback
			// 'unknown' agent must be refused — Platform=system, not
			// human. This protects against a misconfigured deploy that
			// pins KOOPA_MCP_CALLER_AGENT="unknown" and a buggy client
			// that mirrors that in `as`.
			name:    "explicit unknown caller — Platform=system refused",
			ctx:     withCallerAs(t.Context(), "unknown"),
			wantErr: `caller "unknown" is not authorized (human-only)`,
		},
		{
			name: "explicit human caller — allowed",
			ctx:  withCallerAs(t.Context(), "human"),
			// wantErr empty: allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.requireExplicitHuman(tt.ctx, "test_op")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("requireExplicitHuman = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("requireExplicitHuman = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("requireExplicitHuman error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRequireAuthor(t *testing.T) {
	s := newTestServer()

	tests := []struct {
		name    string
		ctx     context.Context
		authors []string
		wantErr string
	}{
		{
			name:    "human always allowed regardless of allowlist",
			ctx:     withCallerAs(t.Context(), "human"),
			authors: []string{"hq"},
		},
		{
			name:    "caller in allowlist",
			ctx:     withCallerAs(t.Context(), "hq"),
			authors: []string{"hq", "content-studio"},
		},
		{
			name:    "caller not in allowlist",
			ctx:     withCallerAs(t.Context(), "learning-studio"),
			authors: []string{"hq", "content-studio"},
			wantErr: `caller "learning-studio" is not in the author allowlist`,
		},
		{
			name:    "unregistered caller",
			ctx:     withCallerAs(t.Context(), "ghost"),
			authors: []string{"hq"},
			wantErr: `caller "ghost" is not registered`,
		},
		{
			// CF-02: the zero-privilege fallback agent must be refused
			// by requireAuthor too — even if a client explicitly passes
			// as:"unknown" trying to slip past the env default.
			name:    "explicit unknown caller — refused by allowlist",
			ctx:     withCallerAs(t.Context(), "unknown"),
			authors: []string{"hq", "content-studio"},
			wantErr: `caller "unknown" is not in the author allowlist`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.requireAuthor(tt.ctx, "test_op", tt.authors...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("requireAuthor = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("requireAuthor = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("requireAuthor error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestServerDefaultCallerAgent_FailsClosed pins the CF-02 contract: the
// server's default callerAgent (used when an MCP call omits `as`) is the
// zero-privilege "unknown" agent, and every authorization gate refuses it.
// This test deliberately uses a fresh Server constructed without
// WithCallerAgent, so it observes the bare default from NewServer's
// initializer at server.go.
//
// Why this matters: prior to CF-02, the default was "human", which let
// any caller that omitted `as` silently inherit human authority through
// requireAuthor (the human-implicit branch). The audit author chain for
// such a call would attribute it to "human" even though no human review
// occurred. The default change to "unknown" closes that path: a missing
// `as` now resolves to a Platform=system agent that fails every gate.
//
// The test does NOT exercise the propose/commit/publish handlers because
// the new default is observable at the gate level — extending the test
// to those handlers would duplicate TestRequireExplicitHuman /
// TestRequireAuthor coverage.
func TestServerDefaultCallerAgent_FailsClosed(t *testing.T) {
	// Construct a Server with the same default initializer NewServer uses,
	// without WithCallerAgent. handler_test.go's newTestServer() pins
	// callerAgent="human" for legacy reasons (so unit tests can exercise
	// validation paths past requireAuthor); this test must NOT use that
	// helper, otherwise it would observe the test default, not the
	// production-relevant server default.
	s := &Server{
		logger:         testLogger(),
		registry:       agent.NewBuiltinRegistry(),
		proposalSecret: []byte("test-secret-32-bytes-long-enough"),
		// Mirror server.go NewServer initializer — the value that CF-02
		// hardened. If this drifts from server.go, the test must be
		// updated to match, and the divergence is itself a regression.
		callerAgent: "unknown",
	}

	// 1. requireExplicitHuman: omitting `as` triggers the explicit-`as`
	// guard before ever inspecting the resolved identity. The message
	// names the absence, not the default value.
	if err := s.requireExplicitHuman(t.Context(), "test_op"); err == nil {
		t.Fatal("requireExplicitHuman without `as` = nil, want refusal")
	} else if !strings.Contains(err.Error(), "refusing without explicit `as` field") {
		t.Errorf("requireExplicitHuman error = %q, want explicit-`as` refusal", err)
	}

	// 2. requireAuthor: without `as`, the resolved identity falls back
	// to the server default ("unknown"). The "unknown" registry row has
	// Platform=system (not human) and is not in any allowlist, so the
	// gate rejects with the "not in the author allowlist" path. This is
	// the gate that CF-02 actually hardened — under the old default
	// "human", this branch silently passed via the human-implicit short
	// circuit.
	if err := s.requireAuthor(t.Context(), "test_op", "hq", "content-studio"); err == nil {
		t.Fatal("requireAuthor without `as` (default unknown) = nil, want refusal")
	} else if !strings.Contains(err.Error(), `caller "unknown" is not in the author allowlist`) {
		t.Errorf("requireAuthor error = %q, want unknown-not-in-allowlist refusal", err)
	}

	// 3. Sanity check: an explicit `as: "human"` continues to work. This
	// guards against an over-zealous CF-02 follow-up that closes the
	// explicit-human path too. Phase 2 must NOT break legitimate human
	// authority — only the silent-default-human path.
	if err := s.requireExplicitHuman(withCallerAs(t.Context(), "human"), "test_op"); err != nil {
		t.Errorf("requireExplicitHuman with explicit as=human = %v, want nil", err)
	}
	if err := s.requireAuthor(withCallerAs(t.Context(), "human"), "test_op", "hq"); err != nil {
		t.Errorf("requireAuthor with explicit as=human = %v, want nil", err)
	}
}

// testLogger returns a discard slog logger. authz tests don't assert on
// log output; the local helper avoids the integration_test.go logger
// (which lives behind //go:build integration).
func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestCommitProposalGate covers the type-dependent commit gate. directive
// proposals commit without the human gate (HQ delegation flow); every other
// type requires explicit human authority. The token verification step still
// runs first — the gate fires only after a token is verified, so we use
// genuine signed tokens here to reach the gate.
func TestCommitProposalGate(t *testing.T) {
	s := newTestServer()

	// Sign tokens for each type. Field validity does not matter — the gate
	// runs before commitEntity, and commitEntity is what would consume the
	// fields. Tests for commitEntity field handling live alongside the
	// resolve*Fields helpers.
	mintToken := func(t *testing.T, entityType string) string {
		t.Helper()
		token, err := signProposal(s.proposalSecret, entityType, map[string]any{})
		if err != nil {
			t.Fatalf("signing %s proposal: %v", entityType, err)
		}
		return token
	}

	tests := []struct {
		name    string
		ctx     context.Context
		typ     string
		wantErr string
	}{
		{
			name: "directive — hq self-commit allowed (no human gate)",
			ctx:  withCallerAs(t.Context(), "hq"),
			typ:  "directive",
			// directive commit then fails at commitDirective on missing
			// fields, but the auth gate must not fire — so we accept any
			// error that does NOT mention the human-only refusal.
		},
		{
			name:    "goal — hq commit refused (human-only)",
			ctx:     withCallerAs(t.Context(), "hq"),
			typ:     "goal",
			wantErr: `commit_proposal of goal: caller "hq" is not authorized (human-only)`,
		},
		{
			name:    "learning_plan — learning-studio self-commit refused",
			ctx:     withCallerAs(t.Context(), "learning-studio"),
			typ:     "learning_plan",
			wantErr: `commit_proposal of learning_plan: caller "learning-studio" is not authorized (human-only)`,
		},
		{
			name:    "hypothesis — no explicit `as` refused",
			ctx:     t.Context(),
			typ:     "hypothesis",
			wantErr: "refusing without explicit `as` field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := CommitProposalInput{ProposalToken: mintToken(t, tt.typ)}
			_, _, err := s.commitProposal(tt.ctx, nil, input)

			if tt.wantErr == "" {
				// Auth gate must NOT fire. A downstream commitEntity error
				// (no DB, missing fields) is acceptable; the human-only
				// refusal is not.
				if err != nil && strings.Contains(err.Error(), "is not authorized (human-only)") {
					t.Errorf("commitProposal = %q, gate fired unexpectedly", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("commitProposal = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("commitProposal error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestProposeAuthorGates verifies the rejection arm of each
// propose_<type> handler — the gate must fire before any field-resolve
// or DB lookup. The acceptance arm is covered by the matching
// requireAuthor cases above; reaching past the gate without DB stubs
// would force every test to either spin up a pool or duplicate the
// resolve*Fields logic, which trades real coverage for setup noise.
func TestProposeAuthorGates(t *testing.T) {
	s := newTestServer()

	t.Run("propose_goal rejects learning-studio", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "learning-studio")
		_, _, err := s.proposeGoal(ctx, nil, ProposeGoalInput{Title: "x"})
		if err == nil {
			t.Fatal("proposeGoal = nil; want gate error")
		}
		if !strings.Contains(err.Error(), "propose_goal") || !strings.Contains(err.Error(), "learning-studio") {
			t.Errorf("error = %q, want naming both tool and caller", err)
		}
	})

	t.Run("propose_project rejects learning-studio", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "learning-studio")
		_, _, err := s.proposeProject(ctx, nil, ProposeProjectInput{Title: "x", Slug: "x"})
		if err == nil || !strings.Contains(err.Error(), "propose_project") {
			t.Errorf("proposeProject error = %v, want propose_project gate error", err)
		}
	})

	t.Run("propose_milestone rejects learning-studio", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "learning-studio")
		_, _, err := s.proposeMilestone(ctx, nil, ProposeMilestoneInput{Title: "x"})
		if err == nil || !strings.Contains(err.Error(), "propose_milestone") {
			t.Errorf("proposeMilestone error = %v, want propose_milestone gate error", err)
		}
	})

	t.Run("propose_hypothesis rejects content-studio", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "content-studio")
		_, _, err := s.proposeHypothesis(ctx, nil, ProposeHypothesisInput{
			Claim: "x", InvalidationCondition: "y", Content: "z",
		})
		if err == nil || !strings.Contains(err.Error(), `caller "content-studio" is not in the author allowlist`) {
			t.Errorf("proposeHypothesis error = %v, want allowlist refusal", err)
		}
	})

	t.Run("propose_learning_plan rejects hq", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "hq")
		_, _, err := s.proposeLearningPlan(ctx, nil, ProposeLearningPlanInput{
			Title: "Binary trees", Domain: "leetcode",
		})
		if err == nil || !strings.Contains(err.Error(), `caller "hq" is not in the author allowlist`) {
			t.Errorf("proposeLearningPlan error = %v, want allowlist refusal", err)
		}
	})

	t.Run("propose_learning_domain rejects content-studio", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "content-studio")
		_, _, err := s.proposeLearningDomain(ctx, nil, ProposeLearningDomainInput{
			Slug: "iot", Name: "IoT",
		})
		if err == nil || !strings.Contains(err.Error(), `caller "content-studio" is not in the author allowlist`) {
			t.Errorf("proposeLearningDomain error = %v, want allowlist refusal", err)
		}
	})

	// Acceptance-arm spot checks: requireAuthor with the exact allowlist
	// each handler uses. The handler-level acceptance flow is exercised by
	// existing happy-path tests (TestProposeGoal_HappyPath in handler_test.go
	// runs as the default "human" caller, which is always allowed).
	allowlists := map[string][]string{
		"propose_goal":            {"hq", "content-studio", "research-lab"},
		"propose_project":         {"hq", "content-studio", "research-lab"},
		"propose_milestone":       {"hq", "content-studio", "research-lab"},
		"propose_hypothesis":      {"hq", "learning-studio", "research-lab"},
		"propose_learning_plan":   {"learning-studio"},
		"propose_learning_domain": {"learning-studio", "hq"},
	}
	for tool, authors := range allowlists {
		for _, caller := range authors {
			t.Run("accept "+tool+" caller="+caller, func(t *testing.T) {
				ctx := withCallerAs(t.Context(), caller)
				if err := s.requireAuthor(ctx, tool, authors...); err != nil {
					t.Errorf("requireAuthor(%s, %s) = %v, want nil", tool, caller, err)
				}
			})
		}
	}
}

// TestPlanDayGate verifies the hq+human author rule on plan_day. Only
// the rejection arm goes through the handler — the gate fires before
// any store call. Acceptance is verified via requireAuthor against the
// same allowlist; reaching past the gate would force the test to spin
// up a daily store, which adds setup that doesn't strengthen coverage.
func TestPlanDayGate(t *testing.T) {
	s := newTestServer()

	input := PlanDayInput{Items: []PlanDayItem{{TaskID: "550e8400-e29b-41d4-a716-446655440000"}}}

	t.Run("content-studio rejected", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "content-studio")
		_, _, err := s.planDay(ctx, nil, input)
		if err == nil || !strings.Contains(err.Error(), `caller "content-studio" is not in the author allowlist`) {
			t.Errorf("planDay error = %v, want allowlist refusal", err)
		}
	})

	t.Run("learning-studio rejected", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "learning-studio")
		_, _, err := s.planDay(ctx, nil, input)
		if err == nil || !strings.Contains(err.Error(), `caller "learning-studio" is not in the author allowlist`) {
			t.Errorf("planDay error = %v, want allowlist refusal", err)
		}
	})

	for _, caller := range []string{"hq", "human"} {
		t.Run("accept caller="+caller, func(t *testing.T) {
			ctx := withCallerAs(t.Context(), caller)
			if err := s.requireAuthor(ctx, "plan_day", "hq"); err != nil {
				t.Errorf("requireAuthor plan_day caller=%s = %v, want nil", caller, err)
			}
		})
	}
}

// TestFileReportStandaloneGate verifies the standalone allowlist
// excludes HQ. The rejection arm goes through the handler; the
// acceptance arm uses requireAuthor for the same reason as
// TestPlanDayGate. The task-bound branch (in_response_to set) takes a
// different path and is not covered here.
func TestFileReportStandaloneGate(t *testing.T) {
	s := newTestServer()

	validArtifact := &FileReportArtifactInput{
		Name:  "x",
		Parts: []json.RawMessage{json.RawMessage(`{"text":"hi"}`)},
	}

	t.Run("hq rejected", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "hq")
		_, _, err := s.fileReport(ctx, nil, FileReportInput{Artifact: validArtifact})
		if err == nil || !strings.Contains(err.Error(), `caller "hq" is not in the author allowlist`) {
			t.Errorf("fileReport error = %v, want allowlist refusal", err)
		}
	})

	authors := []string{"content-studio", "research-lab", "learning-studio"}
	for _, caller := range append(authors, "human") {
		t.Run("accept caller="+caller, func(t *testing.T) {
			ctx := withCallerAs(t.Context(), caller)
			if err := s.requireAuthor(ctx, "file_report (standalone)", authors...); err != nil {
				t.Errorf("requireAuthor file_report caller=%s = %v, want nil", caller, err)
			}
		})
	}
}
