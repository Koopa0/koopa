<p align="center">
  <img src="frontend/public/koopa.png" alt="koopa" width="320">
</p>

<p align="center">
  <strong>English</strong> | <a href="README.zh-TW.md">繁體中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-private%20portfolio-555?style=flat" alt="Status: private portfolio"/>
  <img src="https://img.shields.io/badge/license-All%20Rights%20Reserved-555?style=flat" alt="License: All Rights Reserved"/>
  <img src="https://img.shields.io/badge/Go-1.26.1+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go 1.26.1+"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Angular-22-DD0031?style=flat&logo=angular&logoColor=white" alt="Angular 22"/>
  <img src="https://img.shields.io/badge/MCP-Claude-7F77DD?style=flat" alt="MCP"/>
</p>

<p align="center">
  <a href="https://koopa0.dev"><strong>koopa0.dev&nbsp;↗</strong></a>
</p>

**koopa** is a private planning and publication system — your areas, goals, projects, daily work, and publishable writing in one place, with AI agents working inside it.

The agents share one source of truth for work state: they read the same live state you do, instead of whatever you remember to tell them. You stay the only decision-maker — they inspect, draft, and propose; you decide what's kept. Knowledge authoring and retrieval stay in Obsidian／Yomihon.

## Why this exists

You're juggling a lot — responsibilities you keep up, goals you're chasing, projects in flight, a daily list, things you're half-writing. What you want is help keeping it all moving: something that remembers where you left off, surfaces what's slipping, and works alongside you — not just another app you have to feed.

Most AI tools can't be that, because they forget. Every conversation starts from zero, and the more assistants you add, the more time you spend re-explaining yourself. koopa stores the work itself instead — your goals, projects, plans, and writing live in one place every agent can read. So an assistant can pull up your morning briefing, see what you finished yesterday, draft the next piece, and hand it back for your call, without you recapping a thing. It helps you carry the work; it never quietly takes it over.

## How it works

The line that matters isn't human vs. agent — it's flow vs. decision. Agents handle the flow: they inspect current work, draft, and propose, in conversation with you. You handle the decisions: an agent can suggest a new goal or hand in a finished article, but it stays a draft until you accept it in the admin UI. They coordinate through the shared state, never by handing work to each other.

| Who | Role |
|---|---|
| **You** (Koopa) | The only decision-maker |
| **Claude Code** | Development sessions in this repo — inspection, build logs, content drafts |
| **Hermes** | Curates a personal Obsidian vault on a schedule |
| **Codex** | Development collaborator — repo work and code review |

That split is the whole point. Agents can run freely — capture a todo, draft a proposal, push an article to your review queue — precisely *because* the commitments stay yours. Without the gate, autonomy just floods the system with things you never chose to keep.

## What's inside

**Planning & commitments.** Your work is organized PARA + GTD style — areas, goals with milestones, projects, todos, and a daily plan. The daily plan doesn't silently roll yesterday's unfinished work forward; it resurfaces in your morning briefing, so you decide what stays.

**Writing & publishing.** Five kinds of content — articles, essays, build logs, TILs, and digests — move through a simple editorial flow from draft to published. An agent can hand in a finished draft and revise it after you send it back, but you're the only one who publishes.

**Shared context.** Agents read your current planning state through MCP — goals, projects, todos, and the daily plan. Koopa does not copy or search your knowledge base; knowledge authoring and retrieval stay in Obsidian／Yomihon.

**One history.** Every change records who made it, so the whole system keeps a single, trustworthy timeline of what happened and when.

## Scope and limits

This is a single-admin system by design: one person, several AI agents — no team accounts, no roles, no "share with a colleague." The admin side is private; only some content (articles, build logs, TILs) reaches the public site, and only after you publish it. Goals and private notes stay private. Koopa stores planning state and publishes selected writing; the private knowledge base lives in Obsidian. If you want a team wiki or a Notion clone, this isn't it.

## Provider deployment boundary

This repository provides PostgreSQL to the stock trader; it does not own the
shared network. `trader-db` is a **server-owned** external Docker network. Its
creation, validation, and disaster recovery remain canonical in the server
repository's [VPS setup](https://github.com/Koopa0/server/blob/main/VPS-SETUP.md)
and [disaster recovery](https://github.com/Koopa0/server/blob/main/DISASTER-RECOVERY.md)
documents. Do not copy or improvise their network lifecycle commands here.

The coordinated cutover requires Docker Engine 28 or newer and an Engine API
whose container-network inspection exposes array-valued `DNSNames`. From an
independently accepted server checkout, the exact owner-approved existing-VPS
operation is:

```bash
bash ~/server/scripts/ensure-trader-db-network.sh
```

That command must report `TRADER_DB_NETWORK_READY`. This provider must never
create, delete, repair, connect, or disconnect the external network.

The only supported rollout order is **server → provider → consumer**:

1. The server-owned gate creates or validates an empty, unowned `trader-db`.
2. Deploy this provider and wait for its terminal `TOPOLOGY_RECEIPT`. The first
   transition recreates PostgreSQL and interrupts existing database connections;
   use an approved maintenance window and a fresh backup.
3. Only then deploy `tw-stock-trader`; never deploy the consumer first.

The steady-state topology is exact:

- `postgres`: exactly `internal` + `trader-db`, and the sole owner of the
  `postgres` DNS name on `trader-db`;
- `trader`: exactly `trader-db`, without the `postgres` DNS name;
- `trader-db`: exactly those two endpoints, with no Compose ownership labels;
- frontend, backend, MCP, and observability services never join `trader-db`.

The preflight and postflight emit one sanitized diagnostic without Docker
inspect payloads. Use it as a stop reason, not as permission to mutate the
server-owned network manually:

| Diagnostic | Operator action |
|---|---|
| `required trader-db network is missing or unreadable` | Stop and run the canonical server gate; check access there. |
| `base bridge contract mismatch`, `IPv4 NAT egress contract mismatch`, `ICC connectivity contract mismatch`, or `server-owned lifecycle contract mismatch` | Stop; the server-owned network contract is not safe for rollout. Return to the server gate and owner-reviewed recovery. |
| `PostgreSQL endpoint does not own the postgres DNS name` or `trader endpoint DNS names are missing or unreadable` | Confirm Docker Engine/API support for `DNSNames`, then restore and redeploy the provider before any consumer deploy. |
| `postgres DNS name is claimed by the trader endpoint`, `trader endpoint joins networks other than trader-db`, or `contains an unexpected endpoint` | Stop; endpoint ownership has drifted. Keep the consumer stopped and use owner-reviewed provider/consumer rollback. |

Any topology error is a stop condition. Do not deploy the consumer while the
provider gate is red. If the provider cutover fails, restore provider service
before continuing and leave `trader-db` in place. After consumer cutover, never
remove PostgreSQL from `trader-db` or return trader to `internal`: rollback uses
the prior binary with the current secure topology. If that is unavailable, keep
the consumer stopped and return to owner-reviewed recovery.

---

## License

**All Rights Reserved** — see [LICENSE](LICENSE).
