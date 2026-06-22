// Copyright 2026 Koopa. All rights reserved.

// authz.go holds the runtime authorization helpers used by handlers in
// this package. Authorization in the koopa MCP server is layered along
// three orthogonal axes; each gate enforces exactly one axis. Keeping the
// axes separated lets a handler compose them without conflating concerns.
//
// # Authorization axes
//
//  1. Author — is the caller in the allowlist for this domain? Each
//     write tool that crosses a domain boundary (plan_day, …) has a
//     small set of legitimate authors baked into its handler. Author
//     gates are runtime allowlists — adding "may learning-studio author
//     goals" should not require rebuilding the binary or migrating
//     existing rows. Enforced by requireAuthor.
//
//  2. Registration — does the caller resolve to a known, non-fallback
//     agent at all? The weakest identity gate, used by knowledge-base
//     and settings writes that have no domain allowlist but must still
//     refuse the zero-privilege "unknown" fallback. Enforced by
//     requireRegisteredCaller.
//
//  3. Self — is the caller the row's owner? The model reserves this axis
//     for personal-GTD mutations (caller == row.created_by / row.target).
//     No tool on the current MCP surface exercises it — advance_work, its
//     original consumer, is an admin-only HTTP action — so there is no
//     requireSelf helper; a handler that needed it would gate inline
//     against the loaded row.
//
// # Why human is always implicit on author gates
//
// requireAuthor permits Platform=="human" callers regardless of the
// allowlist. The system has exactly one human (Koopa); the human is the
// owner of the entire surface, and an author rule that excluded the
// owner would be incoherent. Allowlists name the cowork agents that
// MAY also author the entity — the human is never on the list because
// the human is never excluded.
//
// # Why the "unknown" fallback fails every gate
//
// The MCP server has a default caller agent (cmd/mcp/config.go:
// KOOPA_MCP_CALLER_AGENT, default "unknown"). The "unknown"
// agent has Platform != "human", so a tool call that omits `as` cannot
// pass requireAuthor (it is neither human nor in any allowlist) nor
// requireRegisteredCaller (it is the zero-privilege fallback sentinel).
// A missing `as` therefore fails closed on every mutating tool.

package mcp

import (
	"context"
	"fmt"
	"slices"

	"github.com/Koopa0/koopa/internal/agent"
)

// requireAuthor gates an operation to a domain-specific allowlist of
// agents. Platform=="human" callers are always permitted regardless of
// the list — see the package doc for why human is implicit.
//
// authors lists the cowork (or claude-code) agents that may author the
// targeted entity in addition to human. An empty list collapses to
// "human only".
func (s *Server) requireAuthor(ctx context.Context, op string, authors ...string) error {
	name := s.callerIdentity(ctx)
	caller, ok := s.registry.Lookup(agent.Name(name))
	if !ok {
		return fmt.Errorf("%s: caller %q is not registered", op, name)
	}
	if caller.Platform == "human" {
		return nil
	}
	if slices.Contains(authors, name) {
		return nil
	}
	return fmt.Errorf("%s: caller %q is not in the author allowlist (allowed: human, %v)", op, name, authors)
}

// unknownAgent is the zero-privilege fallback identity assigned when an MCP
// call omits `as`. It mirrors cmd/mcp/config.go's KOOPA_MCP_CALLER_AGENT
// default and the agent.BuiltinAgents() "unknown" row, which is registered
// ONLY so the audit-trigger actor FK resolves — it is not a real author.
const unknownAgent = "unknown"

// requireRegisteredCaller is the weakest identity gate in the package: it
// asserts only that a mutating call carries a KNOWN author, not that the
// author holds any particular capability or platform. It exists for the
// write tools that previously had no identity gate at all (capture_inbox,
// draft_hypothesis, start_session, record_attempt, end_session, manage_plan),
// where an unregistered or unidentified caller
// could write to the knowledge base.
//
// It reuses the same registry requireAuthor already consults — no parallel
// map — and refuses two callers:
//
//   - an `as` value naming no registry row (a typo or fabricated name):
//     the "is not registered" message matches requireAuthor's;
//   - the unknownAgent sentinel, which is the server default when `as` is
//     omitted (and the value a buggy client might mirror explicitly).
//     "unknown" is registered, so Lookup alone would admit it — but it
//     means "the caller did not identify itself" and is therefore not a
//     known author; a knowledge-base write attributed to it is
//     refused. This mirrors requireAuthor's fail-closed handling of the
//     server's default caller ("unknown" is already rejected there via
//     the allowlist axis).
//
// This gate reads callerIdentity: a personal-use deploy that pins
// KOOPA_MCP_CALLER_AGENT="human" (per config.go) is a real registered author
// and is admitted without an explicit `as`. Only the fail-closed "unknown"
// default is refused.
//
// Finer-grained subdivision — which registered agent may write WHICH entity —
// is intentionally out of scope here.
func (s *Server) requireRegisteredCaller(ctx context.Context, op string) error {
	name := s.callerIdentity(ctx)
	if _, ok := s.registry.Lookup(agent.Name(name)); !ok {
		return fmt.Errorf("%s: caller %q is not registered", op, name)
	}
	if name == unknownAgent {
		return fmt.Errorf("%s: caller %q is the zero-privilege fallback (call omitted `as`); writes require a known author", op, name)
	}
	return nil
}
