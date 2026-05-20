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
contract §8 #N", "see ADR-XXXX", "see audit YYYY-MM-DD §N") — even when the
statement is technically correct. When you patch one instance, sweep ALL
mirror surfaces for that topic; fixing only the one that was caught leaves the
same class leaking elsewhere.
