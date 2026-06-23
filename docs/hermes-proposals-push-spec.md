# Hermes spec — "pull Koopa back to review" push + proposal readback

A one-page spec for the **hermes** repo (NOT koopa0.dev). koopa0.dev exposes the
read endpoints; hermes does the pushing. Forward this to a hermes session.

## Why this exists

Koopa's proposal/triage loop has two halves. The **in-app** half is built on
koopa0.dev (nav badge + a "N proposals awaiting review →" pointer on Today).
The **push** half — something that actively nudges Koopa to *go* review when he
isn't already in the admin — is NOT built, and it lives on the hermes side.
Without it the triage queue risks becoming a graveyard: an in-app-only surface
is one Koopa returns to only when something actively pulls him back to the
proposals triage queue.

## What koopa0.dev already provides (ready to consume)

- `GET /api/admin/commitment/proposals/count` → `{proposed_goals, proposed_areas, proposed_projects}`.
  Sum > 0 means there are agent-proposed area/goal/project drafts awaiting triage.
- MCP `list_tasks(as)` — read-only, **caller-scoped**: returns the todos *you*
  (the calling agent) created, with their state. accept = state todo/done,
  pending = inbox, reject = **absent from the list**.
- MCP `resolve_task(id, state, as)` — caller-scoped terminal-state setter
  (done | archived | dismissed) for todos *you* created. Lets hermes self-close
  items it captured once it has read their disposition.

## What hermes should build

### 1. Daily review nudge (the "pull back")
- In the existing **pa-brief** daily routine (Telegram), add one line when there
  are pending proposals: read `proposals_pending` (sum the count endpoint); if
  `> 0`, emit e.g. `📋 N proposals awaiting review → <admin proposals URL>`.
- **Trigger = the daily pa-brief schedule**, NOT per-proposal. Per-proposal
  pushes = spam (one ping per surface). A once-daily roll-up is the anti-spam.
- **N = 0 → emit nothing** (silent). No "you're all caught up" noise.
- This is a notification, not a write — it does not violate the pull-only rule.

### 2. Capture readback loop (learn Koopa's taste)
- hermes already pushes suggestions into Koopa's inbox via `capture_inbox`
  (created_by=hermes). To close the loop, periodically call `list_tasks(as=hermes)`
  and compare against what hermes captured:
  - present + state todo/done → **accepted** (Koopa kept it)
  - present + state inbox → **pending** (not yet triaged)
  - **absent** → **rejected** (Koopa dropped it)
- Feed accept/reject counts into hermes's own surfacing heuristic (the
  readback.py ledger) so it proposes more of what Koopa keeps, less of what he drops.
- Once hermes has read an item's disposition and is done tracking it,
  `resolve_task(id, state=archived, as=hermes)` to self-clear it.

## Notes / boundaries
- All three tools are caller-scoped: pass `as: "hermes"`. hermes can only read/
  resolve the todos it created — never Koopa's personal todos or another agent's.
- koopa0.dev's MCP + admin share one DATABASE_URL, so a hermes write is visible
  to Koopa's admin immediately (no sync step).
- koopa0.dev will NOT add a Telegram/push dependency to its Go server — the push
  is deliberately hermes-side so the knowledge engine stays dependency-light.
