# Hermes spec — "pull Koopa back to review" push + proposal readback

For the **hermes** repo (NOT koopa0.dev). koopa0.dev exposes the reads on the
MCP surface; hermes does the pushing. Forward this to a hermes session only
after the `proposals` brief section has shipped on koopa0.dev.

## Why this exists

Koopa's proposal/triage loop has two halves. The **in-app** half is built on
koopa0.dev (nav badge + a "N proposals awaiting review →" pointer on Today).
The **push** half — actively nudging Koopa to *go* review when he isn't in
the admin — lives on the hermes side. Without it the triage queue risks
becoming a graveyard: an in-app-only surface is one Koopa returns to only
when something actively pulls him back.

## What koopa0.dev provides (MCP surface — the ONLY access path)

- MCP `brief(mode=morning, sections=["proposals"], as="hermes")` →
  `proposals_pending` (int): agent-proposed area/goal/project drafts awaiting
  owner triage. If the pa-brief routine already pulls a full morning brief,
  read the field from that response instead of making a second call.
- MCP `list_todos(as="hermes")` — read-only, caller-scoped: every todo hermes
  created, as `{id, title, state, created_by}` — `created_by` echoes the
  resolved caller. No filters; no server-side state trim.
- MCP `resolve_todo(id, state, as="hermes")` — caller-scoped terminal setter
  (done | archived | dismissed) on todos hermes created. Read the self-clear
  rules (§3) before calling this — the server enforces creator scope but NOT
  state preconditions.

Do NOT call the koopa0.dev admin HTTP API. hermes never holds admin JWT
credentials; the MCP transport is the agent access boundary.

## What hermes should build

### 1. Daily review nudge (the "pull back")

- In the existing **pa-brief** daily routine (Telegram): read
  `proposals_pending`; if > 0, emit one line:
  `📋 N proposals awaiting review → https://koopa0.dev/admin/commitment/proposals`
- **Trigger = the daily pa-brief schedule**, NOT per-proposal. Per-proposal
  pushes are spam; the once-daily roll-up is the anti-spam.
- **N = 0 → emit nothing** (silent). No "all caught up" noise.
- This is a notification, not a write — it does not violate the pull-only rule.

### 2. Capture readback loop (learn Koopa's taste)

- At capture time, record in the readback ledger: the returned `todo.id`
  (`capture_inbox` returns the full created todo) and **whether the capture
  carried recurrence** — that flag gates §3.
- Periodically call `list_todos(as="hermes")` and map each ledger id:

  | observed | meaning | taste signal |
  |---|---|---|
  | absent | Koopa dropped it from inbox | **rejected** |
  | `inbox` | not yet triaged | pending |
  | `todo` / `in_progress` | accepted, live in Koopa's GTD | **accepted** |
  | `someday` | accepted but deferred | accepted (weak) |
  | `done` | accepted and completed | **accepted (strong)** |
  | `archived` / `dismissed` | hermes set this itself earlier | already processed — skip |

  (`archived`/`dismissed` cannot come from the admin UI; on hermes-created
  rows they can only be hermes's own prior resolve.)
- Feed accept/reject counts into hermes's surfacing heuristic (the readback.py
  ledger) so it proposes more of what Koopa keeps, less of what he drops.

### 3. Self-clear rules (STRICT — no server-side state guard)

- **MAY** archive a row in **state=done** once its disposition is recorded:
  `resolve_todo(id, "archived")` — EXCEPT ids the ledger flags as recurring.
- **MAY** dismiss a row still in **state=inbox** that hermes decides to
  retract: `resolve_todo(id, "dismissed")`.
- **MUST NOT** resolve rows in state `todo` / `in_progress` / `someday` —
  those are Koopa's live todos; archiving one deletes it from his active
  surface.
- **MUST NOT** archive/dismiss any id captured with recurrence — that stops
  Koopa's routine. `list_todos` does not expose recurrence; rely on the
  capture-time ledger flag.
- **MUST NOT** set `state=done`. Completion is Koopa's signal, not hermes's;
  on recurring todos `done` even completes today's occurrence on his behalf.

## Notes / boundaries

- Pass `as: "hermes"` on every call. All three tools are caller-scoped:
  hermes can only read/resolve the todos it created — never Koopa's personal
  todos or another agent's.
- koopa0.dev's MCP + admin share one DATABASE_URL, so a hermes write is
  visible in Koopa's admin immediately (no sync step).
- koopa0.dev will NOT add a Telegram/push dependency to its Go server, and
  will NOT hand agents admin API credentials — the push is deliberately
  hermes-side, the reads deliberately MCP-side.
