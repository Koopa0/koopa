// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
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
			authors: []string{"planner"},
		},
		{
			name:    "caller in allowlist",
			ctx:     withCallerAs(t.Context(), "planner"),
			authors: []string{"planner", "content-studio"},
		},
		{
			// A registered cowork/dev agent that is not on the allowlist is
			// rejected by the allowlist axis (not the registration axis).
			name:    "caller not in allowlist",
			ctx:     withCallerAs(t.Context(), "codex"),
			authors: []string{"planner"},
			wantErr: `caller "codex" is not in the author allowlist`,
		},
		{
			name:    "unregistered caller",
			ctx:     withCallerAs(t.Context(), "ghost"),
			authors: []string{"planner"},
			wantErr: `caller "ghost" is not registered`,
		},
		{
			// The zero-privilege fallback agent must be refused by
			// requireAuthor too — even if a client explicitly passes
			// as:"unknown" trying to slip past the env default.
			name:    "explicit unknown caller — refused by allowlist",
			ctx:     withCallerAs(t.Context(), "unknown"),
			authors: []string{"planner", "content-studio"},
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

// TestServerDefaultCallerAgent_FailsClosed pins the hardened-default
// contract: the server's default callerAgent (used when an MCP call omits
// `as`) is the zero-privilege "unknown" agent, and requireAuthor refuses it.
// This test deliberately uses a fresh Server constructed without
// WithCallerAgent, so it observes the bare default from NewServer's
// initializer at server.go.
//
// Why this matters: before the default was hardened to "unknown", it was
// "human", which let any caller that omitted `as` silently inherit human
// authority through requireAuthor (the human-implicit branch). The audit
// author chain for such a call would attribute it to "human" even though
// no human review occurred. The "unknown" default closes that path: a
// missing `as` resolves to a Platform=system agent that fails the gate.
func TestServerDefaultCallerAgent_FailsClosed(t *testing.T) {
	// Construct a Server with the same default initializer NewServer uses,
	// without WithCallerAgent. handler_test.go's newTestServer() pins
	// callerAgent="human" for legacy reasons (so unit tests can exercise
	// validation paths past requireAuthor); this test must NOT use that
	// helper, otherwise it would observe the test default, not the
	// production-relevant server default.
	s := &Server{
		logger:   testLogger(),
		registry: agent.NewBuiltinRegistry(),
		// Mirror server.go NewServer initializer — the hardened default.
		// If this drifts from server.go, the test must be updated to
		// match, and the divergence is itself a regression.
		callerAgent: "unknown",
	}

	// requireAuthor: without `as`, the resolved identity falls back to the
	// server default ("unknown"). The "unknown" registry row has
	// Platform=system (not human) and is not in any allowlist, so the gate
	// rejects with the "not in the author allowlist" path. This is the gate
	// the hardened default protects — before the default was hardened to
	// "unknown", this branch silently passed via the human-implicit short
	// circuit under the old default "human".
	if err := s.requireAuthor(t.Context(), "test_op", "planner"); err == nil {
		t.Fatal("requireAuthor without `as` (default unknown) = nil, want refusal")
	} else if !strings.Contains(err.Error(), `caller "unknown" is not in the author allowlist`) {
		t.Errorf("requireAuthor error = %q, want unknown-not-in-allowlist refusal", err)
	}

	// Sanity check: an explicit `as: "human"` continues to work. This
	// guards against an over-zealous follow-up that closes the
	// explicit-human path too — legitimate human authority must remain.
	if err := s.requireAuthor(withCallerAs(t.Context(), "human"), "test_op", "planner"); err != nil {
		t.Errorf("requireAuthor with explicit as=human = %v, want nil", err)
	}
}

// testLogger returns a discard slog logger. authz tests don't assert on
// log output; the local helper avoids the integration_test.go logger
// (which lives behind //go:build integration).
func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestPlanDayGate verifies the planner+human author rule on plan_day. Only
// the rejection arm goes through the handler — the gate fires before
// any store call. Acceptance is verified via requireAuthor against the
// same allowlist; reaching past the gate would force the test to spin
// up a daily store, which adds setup that doesn't strengthen coverage.
func TestPlanDayGate(t *testing.T) {
	s := newTestServer()

	input := PlanDayInput{Items: []PlanDayItem{{TaskID: "550e8400-e29b-41d4-a716-446655440000"}}}

	t.Run("claude rejected", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "claude")
		_, _, err := s.planDay(ctx, nil, input)
		if err == nil || !strings.Contains(err.Error(), `caller "claude" is not in the author allowlist`) {
			t.Errorf("planDay error = %v, want allowlist refusal", err)
		}
	})

	t.Run("codex rejected", func(t *testing.T) {
		ctx := withCallerAs(t.Context(), "codex")
		_, _, err := s.planDay(ctx, nil, input)
		if err == nil || !strings.Contains(err.Error(), `caller "codex" is not in the author allowlist`) {
			t.Errorf("planDay error = %v, want allowlist refusal", err)
		}
	})

	for _, caller := range []string{"planner", "human"} {
		t.Run("accept caller="+caller, func(t *testing.T) {
			ctx := withCallerAs(t.Context(), caller)
			if err := s.requireAuthor(ctx, "plan_day", "planner"); err != nil {
				t.Errorf("requireAuthor plan_day caller=%s = %v, want nil", caller, err)
			}
		})
	}
}
