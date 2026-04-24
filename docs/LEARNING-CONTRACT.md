# Learning — Consumer Contract

> Scope: the learning subsystem exposes two independent signals. This
> document pins down what each one means, who writes it, who reads it,
> and where the coupling is — and is not. Read this before assuming a
> dashboard value implies a write path.

## Two parallel signals, coupled only at the write call

Every `record_attempt` call writes to both layers in one pass, but the
layers serve different questions:

| Layer | Scope | Answers |
|---|---|---|
| **FSRS retention** (`review_cards`) | per `learning_target` | "When should I next review **this specific problem / chapter / drill** to maximise retention?" |
| **Concept mastery** (`learning_attempt_observations`) | per `concept` (aggregated across targets) | "Which **patterns / skills / principles** do I understand vs still get wrong?" |

They are **intentionally separate axes**. Solving a LeetCode problem
today does not update your mastery of `binary-search` as a concept; it
only advances the FSRS interval of that problem. Mastery advances when
multiple observations across multiple targets accumulate for the same
concept.

## `learning_dashboard(view=...)` — what reads what

| View | Source | Keyed by |
|---|---|---|
| `retrieval` | `review_cards.due` | learning_target |
| `mastery` | aggregated `learning_attempt_observations` | concept |
| `weaknesses` | aggregated `learning_attempt_observations` WHERE signal_type='weakness' | concept |
| `overview` | aggregates both layers (non-overlapping) | mixed |
| `timeline` | `learning_sessions` | session |
| `variations` | `learning_target_relations` | target pair |

**Rule of thumb**: if a view is keyed by concept, it ignores FSRS. If it
is keyed by learning_target, it ignores mastery observations.

## `record_attempt` writes — the full picture

One attempt call fans out to at most three write paths:

1. **Attempt row** (`learning_attempts`) — append-only, mandatory.
2. **Observations** (`learning_attempt_observations`) — zero or more
   per attempt, one per (concept, signal) tuple supplied in the input.
   Each observation has a `category` FK to `observation_categories` —
   typos are rejected at write, not silently split in dashboard GROUP BY.
3. **FSRS review** (`review_cards` + `review_logs`) — the target's card
   is advanced using either the outcome-derived rating **or** an explicit
   `fsrs_rating` override.

The three write paths are independent after the attempt row persists:
if FSRS fails, the attempt and observations still land. Failure is
surfaced via `fsrs_review_failed: true` on the response *and* stamped on
`review_cards.last_sync_drift_at` so the retrieval view can warn on
subsequent reads (see `drift_suspect` below).

## `fsrs_rating` is REPLACE, not AUGMENT

When `fsrs_rating` is supplied on `record_attempt`:

- FSRS records **only the override**. The outcome-derived rating is
  completely bypassed.
- Observations are still derived from `outcome` and stored normally.

Practical consequence: `solved_with_hint` + `fsrs_rating: 4` tells FSRS
"Easy" (long interval) while telling mastery analytics "needed a hint"
(improvement/weakness signal). That is the use case — recall difficulty
diverging from solve outcome. But make sure that is what you mean: it is
not "Easy AND solved_with_hint informed FSRS"; it is "Easy, and outcome
went to observations only."

| Caller sends | FSRS sees | Observations see |
|---|---|---|
| `outcome=solved_independent` | rating=Good (from outcome) | signal per input |
| `outcome=solved_with_hint` | rating=Hard (from outcome) | signal per input |
| `outcome=solved_with_hint`, `fsrs_rating=4` | rating=Easy (override) | signal per input |
| `outcome=solved_independent`, `fsrs_rating=2` | rating=Hard (override) | signal per input |

## Outcome → FSRS rating mapping

| Outcome | Paradigm | FSRS rating |
|---|---|---|
| `solved_independent` | problem_solving | Good (3) |
| `completed` | immersive | Good (3) |
| `solved_with_hint` | problem_solving | Hard (2) |
| `solved_after_solution` | problem_solving | Hard (2) |
| `completed_with_support` | immersive | Hard (2) |
| `incomplete` | shared | Again (1) |
| `gave_up` | shared | Again (1) |

**Unknown outcome → error**, not silent fallback. `ratingFromOutcome`
returns `fsrs.ErrUnknownOutcome`; the caller marks
`review_cards.last_sync_drift_at` so the retrieval view surfaces the
drift instead of resetting the interval with a guessed rating. Adding a
new outcome enum value is a compile-time event — the switch must be
updated alongside the schema enum.

## `drift_suspect` — how to read it as a consumer

`RetrievalTarget.drift_suspect` is true when:

- `review_cards.last_sync_drift_at` IS NOT NULL, AND
- `last_sync_drift_at` is more recent than the target's latest attempt.

Meaning: the last attempt on this target could not be applied to FSRS
cleanly. The card's `due` may be stale. Choices:

- **Trust attempt history**: skip the item this session (you just did it).
- **Re-review manually**: explicitly re-rate the target so FSRS recalculates.
- **Investigate**: read `drift_reason` (e.g. `unknown_outcome`,
  `review_failed`) and fix the vocabulary/infra issue before more attempts
  accumulate drift.

A successful review (`UpdateCardState`) clears both `last_sync_drift_at`
and `last_drift_reason` — drift is only marked, never sticky.

## What is NOT coupled

These are real-sounding coupling candidates that are explicitly absent:

- **Concept mastery does not extend FSRS intervals.** Three `mastery`
  observations on `binary-search` do not push every binary-search
  target's `due` date out. FSRS is per-target; mastery is per-concept.
- **FSRS due does not imply weakness.** A card being due means "time
  elapsed since last rating, schedule says revisit" — not "you are weak
  at this."
- **Observations do not auto-create FSRS reviews.** Observations without
  an attempt are not a valid write path; observations always flow
  through `record_attempt`.

If you want a concept-driven drill (practice target chosen to exercise a
specific weak concept), use `recommend_next_target` which reads both
layers — it is the only tool that joins them.

## Where to extend this contract

- **Adding a paradigm** (e.g. `rubric_based` for system-design mock
  interviews): add an enum arm to `paradigm` and
  `chk_learning_attempts_paradigm_outcome`, add the new outcomes to
  `ratingFromOutcome`, and update this doc's Outcome→Rating table.
- **Adding a signal_type** (e.g. something beyond weakness/improvement/
  mastery): update the CHECK on `learning_attempt_observations.signal_type`
  and decide explicitly whether mastery aggregation should include the
  new type. Update dashboard queries accordingly.
- **Adding an observation category**: insert a row in
  `observation_categories` with the domain. The FK will accept writes
  immediately.

## Related docs

- `migrations/001_initial.up.sql` — schema, authoritative on columns/
  constraints/triggers.
- `.claude/rules/mcp-decision-policy.md` — which tool writes which entity,
  proposal vs direct commit, agent-note kind binding.
- `docs/SYSTEM-SEMANTICS.md` — system-wide domain model + entity catalogue.
