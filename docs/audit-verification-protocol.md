# Audit & Verification Protocol

> Read before any audit, verification, or doc/code reconciliation task on
> koopa. It exists because "I ran it and it passed" is a claim, not evidence;
> this protocol defines what counts as evidence. Repo-level and tracked, so
> every contributor — human or AI — inherits it. NOT per-session memory.

## 1. Tracked-state precheck
Verify the *tracked* repo, not just the working tree. Run `git status
--porcelain`; it must be clean of build-relevant untracked files. If unsure
whether an untracked file props up the build, prove independence:
`git stash -u && go build ./... && git stash pop`. Treat `git ls-files <f>`
and `git check-ignore <f>` as the truth for "is this in the repo."
**Working tree green ≠ repo green** — a clean checkout, CI, and deploy see
only committed state. (`.claude/` and `CLAUDE.md` are gitignored here; edits
to them never reach the repo.)

## 2. Foreground-only for verification
Any command whose pass/fail you will cite (build / vet / test / lint) runs in
the **foreground**. Background is for exploratory work only (grep, discovery)
— never for a command whose result lands in a conclusion.

## 3. Exit-code provenance
Before citing "exit 0 / passed," the exit code MUST come from the verified
command itself. Read `$?` immediately after it, with **no intervening
statement**. NEVER trust an exit that passed through a pipe, `tee`, `&&`, a
trailing `echo`, or a harness "completed (exit code N)" summary — those
report the *wrapper's* exit, not the command's. Use `cmd > /tmp/out 2>&1`
then `echo "x_exit=$?"`, or `cmd; echo "x_exit=$?"`. Shell-specific gotchas
matter: **zsh does not word-split unquoted variables and lacks bash's
`$PIPESTATUS`**, so an empty-looking grep result or a pipeline exit code may
not behave the way bash habits suggest — verify shell assumptions before
trusting an empty or zero result. A broken provenance voids the conclusion —
rerun.

## 4. Stdout evidence required
Every key verification conclusion attaches concrete output — ≥1 line of
stdout/stderr, or the result file's contents — not a bare exit code. The `ok`
lines, the `0 issues.`, the diff hunk *are* the evidence. A conclusion citing
only an exit code is provisional.

## 5. Cross-validation triage
For each finding from another review (human or AI), answer with exactly one of
**confirm / refine / reject**. `refine` MUST state both what the other review
got right *and* what needs correcting. `reject` MUST attach counter-evidence
(file:line or command output). Bare "agreed" / "disagree" is not triage.

## 6. Authority is descriptive; markers are sticky and domain-level
Three linked rules — the densest and most load-bearing:

**(a) Authority resolves descriptive conflicts only.** The authority order
(schema > code+tests > MCP catalog/policy > contract > skills > historical)
decides *what the system currently does* — when code/schema and prose
disagree on behavior, the higher tier wins and the doc is updated to describe
reality. It does **NOT** resolve *normative* questions — whether that behavior
is intended, or should be kept / removed / changed. **"Code wins" means "the
doc must describe what the code does," never "the code's behavior is the
endorsed design." The existence of a behavior in code is NEVER sufficient to
settle a normative question.**

**(b) Open-question markers are sticky.** Anything a prior audit / contract /
TODO explicitly marked `open` / `decision-pending` / `unresolved` MUST NOT be
closed by a later session. Closing requires explicit human resolution *in the
same session* — not inference from "the code does X." Silently flipping a
marker from open → resolved is *actively overwriting recorded uncertainty*,
which is worse than forgetting to ask.

**(c) Markers are domain-level, not per-file.** An open question spreads
across mirror surfaces (contract, README, ADRs, code comments). Every surface
that states the current behavior of a pending-decision topic MUST carry a
pointer to the canonical record of that decision's status (e.g., "see backend
contract §8 #N", "see ADR-XXXX", "see audit YYYY-MM-DD §N") — **even when the
statement is technically correct about the current state**. Technical accuracy
of a status-quo description does not exempt it from carrying the marker
pointer: the reader needs to know not just *what* the system currently does,
but *whether that current behavior is settled or pending*. A mirror surface
that states current behavior accurately but omits the pending-decision pointer
creates the illusion of a settled state. When you patch one instance, sweep
ALL mirror surfaces for that topic; fixing only the one that was caught leaves
the same class leaking elsewhere.

## 7. Forced changes within scope
A declared scope boundary (file set, package boundary, "do not touch X" list)
can collide with a mechanical dependency cascade that the original plan did not
anticipate: a schema edit forces sqlc regen which forces consumer code retypes;
an interface change forces every call site to update; a `go.mod` bump forces
downstream API adjustments. When this happens, **the boundary may be extended
without violating scope discipline**, but only if all four conditions hold:

**(a)** The change is mechanically forced by an in-scope edit and observable as
a verification blocker — for example a compiler error, sqlc/codegen drift,
typecheck failure, test failure, lockfile/package resolution failure, or
generated artifact mismatch attributable to the in-scope edit. Removing or
reverting the in-scope edit would also remove that blocker. "Forced" is not
"convenient" or "while I'm here." If you can complete and verify the in-scope
work without this change, it is opportunistic, not forced.

**(b)** The change is bounded to the minimum needed to restore green
verification while preserving the approved in-scope objective. The actor must
choose the narrowest path through the cascade, not the cleanest architecture
reachable from the cascade. No consolidation of newly-redundant code, no
refactor of adjacent code that "now obviously could be cleaner," no comment
cleanup on lines you touched. Pure mechanical retype / API adjustment / version
bump propagation.

**(c)** All original guardrails remain intact. Semantic scope, not-touch-X
lists, behavior-change prohibitions, package boundaries that were declared at
the start still hold. The forced change extends the *file set*; it does not
extend the *semantic scope*.

**(d)** The extension is surfaced before commit and either explicitly approved
by the human owner at discovery time or covered by an explicit pre-authorization
envelope in the task text. Goal-mode / autonomous execution is not
pre-authorization. If no approval path is available, leave the diff uncommitted,
report the forced cascade with command/output evidence, and stop.

The defining property: **a correctly-handled forced change makes the human's
approval load smaller, not larger**. The cascade was always going to happen —
surfacing it lets the human approve once with full context, rather than
discover unexpected file changes during review.

Forced changes do NOT violate scope discipline. *Failing to surface them* does.

## 8. Numerically verifiable claims must be locally re-verified
When a downstream artifact repeats or relies on a specific count, length, exit
code, line number, package count, enum/member count, or other discrete value —
including a value that appeared in multiple upstream reviews — the downstream
actor must independently verify the value against ground truth before
propagating it. Trusting an upstream reviewer's number is not verification — it
is a citation without a fact check.

This is the dual of clause 6(a): code is descriptive ground truth at the bottom
of the authority order. Counts about code must come from code (`git grep -c`,
`wc -l`, reading the actual file), not from intermediate text. This also
specializes clause 4's stdout-evidence rule: exact measurements require
reproducible measurement evidence, not just cited prose.

Cross-validation between reviewers can confirm *directions* (this finding is
real, this argument holds), but cannot confirm *measurements* unless each
reviewer measures. **Agreement between reviewers is not evidence for a
measurement unless the agreement includes independently reproduced measurement
evidence.**

The failure mode this prevents: one upstream actor miscounts, two downstream
reviewers cross-validate the conclusion (which is correct) without re-measuring
(which is wrong), and the miscount lands in a tracked artifact. The artifact is
then cited as authoritative for the miscount.

**Operational rule:** if your output contains a discrete number sourced from
someone else's text, you owe the reader a locator or command/output evidence
produced or re-verified in this task. Repeating an upstream command, upstream
line number, or upstream count is not local verification unless you actually
re-read or re-ran the evidence. If you cannot produce that evidence, do not
write the number — write "[count to verify]" and surface the gap.

## 9. Environment-aware tool usage
The git+grep+read baseline is the *floor* of investigative work, not the
ceiling. When the environment provides configured tools — MCP servers,
subagents, skills, hooks, project-specific search tools — **the actor must
inventory and consider them before defaulting to baseline tools**. Skipping the
inventory means working below the environment's intended capability and produces
lower-quality findings than the human reasonably expected.

**Mandatory at the start of any protocol-governed audit, reconciliation,
verification, or acceptance-review task:**

**(a)** Use the environment's available inspection mechanisms to inventory
configured tool surfaces: MCP servers, subagents, skills, hooks, and
project-specific tooling. In a Claude Code environment this includes
MCP/resource listing where available and filesystem scans of `.claude/`,
`skills/`, or equivalent project-local configuration. If no such tools are
configured or discoverable, state that baseline git+grep+read is the available
toolset.

**(b)** Classify each plausibly relevant tool individually. Relevant tools must
be assigned to a specific step ("I will use auggie for the cross-domain sweep in
step N"). Irrelevant tools may be grouped by capability class with one reason
per group, unless a tool's name, role, or configured description makes it
plausibly relevant to the task.

**(c)** The inventory and assignments are surfaced in the output, not held
internally. The human reviewer must be able to verify after-the-fact that the
tools were actually used as declared, by checking the transcript for the
corresponding tool invocations. A tool listed as "relevant, will use in step N"
but never invoked must be surfaced as a deviation before final output, with the
reason. Silent non-use is worse than an honest "no relevant tools available" —
the first is ceremony, the second is evidence.

This clause exists because **a tool that is configured but never called is
functionally equivalent to a tool that does not exist**, and the human who
configured it cannot tell the difference from the output alone. The inventory
step makes tool usage falsifiable.
