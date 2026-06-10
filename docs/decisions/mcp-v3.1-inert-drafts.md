# MCP v3.1 — Inert Drafts (amendment to the v3 contraction)

**Status: ACCEPTED 2026-06-10 (owner decision).** Amends
`mcp-v3-semantic-contraction.md`; everything not amended here stands.

## The principle

The v3 contraction protected agent overreach entity-by-entity. This amendment
restates the boundary as one rule with two protected verbs:

1. **生效 (making things count)** — activation, endorsement, publish,
   verdict. Always human.
2. **結構 (shaping the world)** — areas, learning domains, concept
   hierarchy. Always human.

Everything else — drafting, capturing, suggesting, organizing — agents may
do, provided the artifact is **inert**: it feeds no dashboard, counts toward
no progress, appears in no briefing or default search, and carries explicit
`created_by` attribution. An inert draft is not a decision; it is prepared
material awaiting the human stamp. The system already speaks this grammar
(todo inbox → clarify, content draft → publish, note seed → evergreen,
plan draft → active); the amendment extends it deliberately instead of
entity-by-entity exception.

## Binding constraints

- **Conversation-derived only.** An agent may materialize a draft only from a
  conversation the owner participated in. Scheduled/cron runs never deposit
  drafts. Without this rule, inert drafts become a queue of unrequested
  decisions — the failure mode is not "the system decided for me" but "the
  system nags me".
- **Surface budget.** The agent tool surface stays ≤ 15 tools until a
  deliberate review. Additions spend budget; the ratchet needs a brake.
- **Never opened, permanently:** content `article` and `essay` drafting by
  agents. These are the owner's voice; fluent agent drafts exert gravity that
  no publish gate can catch. (`digest` may be revisited — it is aggregation,
  not voice.)

## Adopted now

**Hypothesis drafts** — the first (and currently only) implementation:

- New initial state `draft` ahead of the existing
  `unverified → verified | invalidated | archived` machine. Agent-created
  hypotheses land in `draft`; admin-created continue to land in `unverified`
  (creating in admin *is* the endorsement).
- Inert: excluded from `brief(morning)`, the Today page, and every dashboard.
  Visible only in the admin hypotheses list as a drafts group.
- MCP gains one flat tool: `draft_hypothesis` (claim*, invalidation_condition*,
  observed_date?, content?) — registered-caller write, like `capture_inbox`.
  Surface becomes 12.
- Admin gains `POST …/hypotheses/{id}/endorse` (draft → unverified) and
  draft-only DELETE. Verdicts (`verify` / `invalidate`) remain human, forever.

Rationale for hypothesis going first: the coach is the party that *sees* the
pattern ("graph 題每次卡在 DFS 終止條件") — this is the entity where agent
observation has the largest comparative advantage, and the learning loop is
the only flow with real usage data today.

## Deferred until real daily-loop usage justifies them

goal / project drafts, milestone suggestions under active goals, agent
`advance` verbs (complete/defer). Candidates, not commitments — usage
produces the ordering, not design taste.
