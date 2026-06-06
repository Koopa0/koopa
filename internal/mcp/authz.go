// Copyright 2026 Koopa. All rights reserved.

// authz.go holds the runtime authorization helpers used by handlers in
// this package. Authorization in the koopa MCP server is layered along
// four orthogonal axes; each gate enforces exactly one axis. Keeping the
// axes separated lets a handler compose them (capability + platform, for
// example) without conflating the concerns.
//
// # Authorization axes
//
//  1. Capability — does the calling agent have the transport-layer right
//     to do this kind of work? Three flags live on agent.Capability:
//     SubmitTasks, ReceiveTasks, PublishArtifacts. Enforced at compile
//     time via agent.Authorize, returning agent.Authorized values that
//     coordination-store mutation methods require in their signatures.
//     Capability is intentionally narrow: it answers "may this caller
//     speak on this channel" not "is this caller the right author of
//     this entity".
//
//  2. Platform — is the caller human? Some operations
//     (publish_content, commit_proposal of high-commitment entities) are
//     reserved for the human owner of the system. The check looks up
//     the agent in the registry and asserts Platform == "human" rather
//     than hardcoding name == "human" — a future trusted auto-publisher
//     agent registered with Platform="human" would inherit the right
//     without code changes.
//
//  3. Author — is the caller in the allowlist for this domain? Each
//     write tool that crosses a domain boundary (plan_day, propose_goal,
//     propose_learning_plan, …) has a small set of legitimate authors
//     baked into its handler. Author gates are runtime allowlists, not
//     capabilities — adding "may content-studio author goals" should
//     not require rebuilding the binary or migrating existing rows.
//
//  4. Self — is the caller the row's owner? Personal-GTD tools
//     (advance_work) and task-bound coordination (file_report with
//     in_response_to, task_detail) require caller == row.created_by /
//     row.target. Enforced inline by the handler against the loaded
//     row; no helper here because the row source varies.
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
// # Why explicit `as` matters for human-only gates
//
// The MCP server has a default caller agent (cmd/mcp/config.go:
// KOOPA_MCP_CALLER_AGENT, default "unknown" since CF-02). The
// "unknown" agent is zero-privilege (no Capability flags, Platform
// != "human"), so a tool call that omits `as` cannot pass
// requireExplicitHuman OR requireAuthor: the former rejects because
// `as` was not explicit, the latter rejects because "unknown" is
// neither human nor in any author allowlist.
//
// requireExplicitHuman additionally enforces that the caller supplied
// `as` explicitly — even an explicit `as: "human"` is required for
// operations like publish_content. This double-gate exists so a
// future env-default override (e.g. KOOPA_MCP_CALLER_AGENT="human"
// for a personal-use deploy) cannot reopen the fail-open path that
// CF-02 closed: requireExplicitHuman refuses ALL default-fall-through
// regardless of what the default points to.
//
// The distinction matters specifically for commit_proposal of
// high-commitment entities and for publish_content, where human
// review is the load-bearing semantic — not a configuration default.

package mcp

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/agent"
)

// requireExplicitHuman gates an operation to callers whose registry row
// has Platform == "human" AND who supplied an explicit `as` field on
// the MCP request. The server default agent (configured via
// KOOPA_MCP_CALLER_AGENT) MUST NOT bypass this check — see the package
// doc for why.
//
// op is included in the error message so a 422 returned to the caller
// names the operation that refused them ("publish_content: …",
// "commit_proposal: …"). Pass the tool name plus any sub-context that
// helps the caller debug.
func (s *Server) requireExplicitHuman(ctx context.Context, op string) error {
	explicit, name := s.ExplicitCallerIdentity(ctx)
	if !explicit {
		return fmt.Errorf("%s: refusing without explicit `as` field", op)
	}
	caller, ok := s.registry.Lookup(agent.Name(name))
	if !ok {
		return fmt.Errorf("%s: caller %q is not registered", op, name)
	}
	if caller.Platform != "human" {
		// Hand-off hint: if the caller has a proposal_token in hand,
		// the right path is to keep the token in conversation context
		// and ask Koopa (or HQ) to commit. Tokens live 10 minutes per
		// proposal.go; longer hand-offs should re-propose.
		return fmt.Errorf("%s: caller %q is not authorized (human-only). Keep the proposal_token in conversation and ask Koopa or HQ to commit (token lives 10 minutes; re-propose if stale)", op, name)
	}
	return nil
}

// requireAuthor gates an operation to a domain-specific allowlist of
// agents. Platform=="human" callers are always permitted regardless of
// the list — see the package doc for why human is implicit.
//
// authors lists the cowork (or claude-code) agents that may author the
// targeted entity in addition to human. An empty list collapses to
// "human only", which is functionally requireExplicitHuman but without
// the explicit-`as` requirement; prefer requireExplicitHuman for that
// case.
func (s *Server) requireAuthor(ctx context.Context, op string, authors ...string) error {
	name := s.callerIdentity(ctx)
	caller, ok := s.registry.Lookup(agent.Name(name))
	if !ok {
		return fmt.Errorf("%s: caller %q is not registered", op, name)
	}
	if caller.Platform == "human" {
		return nil
	}
	for _, a := range authors {
		if name == a {
			return nil
		}
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
// track_hypothesis, start_session, record_attempt, end_session, manage_plan,
// create_note, update_note, update_note_maturity, manage_feeds), where an
// unregistered or unidentified caller could write to the knowledge base /
// settings.
//
// It reuses the same registry requireAuthor / requireExplicitHuman /
// agent.Authorize already consult — no parallel map — and refuses two
// callers:
//
//   - an `as` value naming no registry row (a typo or fabricated name):
//     the "is not registered" message matches requireAuthor's;
//   - the unknownAgent sentinel, which is the server default when `as` is
//     omitted (and the value a buggy client might mirror explicitly).
//     "unknown" is registered, so Lookup alone would admit it — but it
//     means "the caller did not identify itself" and is therefore not a
//     known author; a knowledge-base / settings write attributed to it is
//     refused. This mirrors the fail-closed posture CF-02 established for
//     requireExplicitHuman / requireAuthor (both already reject "unknown"
//     via the platform / allowlist axis).
//
// Unlike requireExplicitHuman, this gate reads callerIdentity (not
// ExplicitCallerIdentity): a personal-use deploy that pins
// KOOPA_MCP_CALLER_AGENT="human" (per config.go) is a real registered author
// and is admitted without an explicit `as`. Only the fail-closed "unknown"
// default is refused.
//
// Capability subdivision — which registered agent may write WHICH entity —
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
