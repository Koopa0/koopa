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
  <img src="https://img.shields.io/badge/pgvector-1536d-378ADD?style=flat" alt="pgvector"/>
</p>

> **Status: private portfolio / source-visible reference — not open source.**
> See [LICENSE](LICENSE): All Rights Reserved. The code is published for portfolio
> and reference reading; it is not open for external use, fork, or contribution.
> This is a single-admin system by design, not a community project.

**koopa** is a private-by-default personal OS where AI agents share a semantic runtime — so the AI reads your state, not your prompts.

It's 8 a.m. You ask for the day. The planner doesn't ask what's on your plate — it reads yesterday's unfinished daily plan, this week's goal progress, the learning targets your last sessions flagged as weak, and the RSS highlights the ingest pipeline collected overnight, and hands you one briefing. You skim it, set today's plan, and start. Through the day the agents stay in their lane: the planner sets the day, the learning coach runs a practice session, any agent searches the corpus or co-authors a note — all in conversation with you. Nothing high-stakes happens behind your back: every goal, project, milestone, and published article is **your** decision, made in the admin UI. The agents surface structure; you make the call.

## Why this exists

Most AI integrations are stateless: every conversation starts from zero, every agent is a fresh amnesiac, and you spend your time re-explaining context. The more agents you add — Claude Code in your editor, Cowork agents on schedulers, background summarizers — the worse it gets, because each produces output the others never see.

koopa models the work instead. Goals, projects, todos, learning attempts, daily plans, content drafts, cognitive observations — all first-class entities with precise schemas and their own lifecycles, in one store every agent reads and writes through MCP. When the learning coach opens a practice session, it already knows which concepts you struggled with last week and which plan you're executing. When the planner assembles your morning briefing, it reads yesterday's daily plan and surfaces what didn't get done — not because you summarized it, but because the state is there. Understanding is queried, not reconstructed; there is no drift between agents and no "I think you mentioned…".

## How it works

The actor axis is **flow vs. decision**, not human vs. agent:

- **Agents drive flows** through a small MCP toolset, in conversation with you.
- **You are the sole decision-maker _and_ the sole router.** Coordination is the shared state in the database, not a message bus — agents read each other's effects through the schema, never through direct dispatch.
- **The admin UI is where you confirm, decide, and view** — it owns every high-commitment write.

The working roster (`internal/agent/registry.go::BuiltinAgents()`):

| Identity | Runs as | Role |
|---|---|---|
| `planner` | Claude Cowork | Morning briefing, candidate day plans, inbox capture, search, note co-author |
| `learning-studio` | Claude Cowork | Learning coach — sessions, attempts, curriculum |
| `koopa0-dev` / `go-spec` | Claude Code | Development sessions in this repo |
| `codex` | Codex CLI | Dev collaborator — repo work and cross-review sessions |
| `hermes` | Claude Code (scheduled) | Curates the personal Obsidian vault on assigned cron jobs |
| `human` | — | Koopa: the only decision-maker, the only router |

Cowork agents run on declared cadences — the planner at 8 a.m., pinned in the registry — but execution is driven by external runners, not by this repo; the backend owns the registry metadata, the schema, and the `process_runs` table that audits each external run.

Writes are gated by **identity**. Every MCP call self-identifies via an `as` field; the server resolves it against the registry and applies three-axis authorization (`internal/mcp/authz.go`): an **author** allowlist (a human is always permitted), **registration** (a known, non-anonymous caller), and **self** (you may only act on your own rows). An unknown caller fails closed on every mutating tool.

Two structural invariants hold:

**Publishing is atomic.** `status='published'`, `is_public=true`, and `published_at=now()` are set in one operation under a joint CHECK constraint, so content cannot leak public by accident.

**Every mutation has an actor.** Each write to a covered entity produces an `activity_events` row via AFTER trigger, carrying the agent name that caused it. Application code cannot insert there directly — the audit log is structural, not voluntary.

### Autonomy with a gate

Agents capture a raw todo to your inbox, draft a note, run a search, recommend the next learning target — useful, low-stakes flows. High-commitment entities — goals, projects, milestones, hypotheses, learning plans, learning domains, and published content — are created **only through the admin UI** (authenticated HTTP), by you. The agent surfaces the option in conversation; you commit it.

That boundary is what makes the autonomy useful: agents can run on their own _because_ the commitment surface is yours. Without it, autonomy floods the system with entities you never decided to keep. A system that makes decisions for you eventually makes you worse at making them.

## The shared semantic runtime

The system models three bounded contexts, each with its own vocabulary and lifecycle:

**Commitment** — PARA + GTD. Areas (ongoing responsibilities), goals (outcomes with optional deadlines), milestones (binary progress checkpoints), projects (execution vehicles), todos (personal GTD items), daily plan items (today's commitments). The daily plan has **no auto-carryover**: yesterday's unfinished work surfaces in the morning briefing but does not roll forward on its own. Confrontation is the feature — silent carryover erodes your relationship with your own commitments.

**Knowledge** — five first-party content types (`article`, `essay`, `build-log`, `til`, `digest`) with an editorial lifecycle (`draft → review → published → archived`); Zettelkasten notes in a separate table with six sub-kinds (`solve-note`, `concept-note`, `debug-postmortem`, `decision-log`, `reading-note`, `musing`) and a maturity lifecycle (`seed → stub → evergreen → needs_revision → archived`); RSS feeds with scheduled fetch and auto-disable on consecutive failures. Content is authored in the admin UI; agents co-author notes via MCP.

**Learning** — a concept ontology, learning targets (individual problems, chapters, drills), sessions with a declared mode, attempts with an outcome taxonomy, confidence-labeled observations, learning plans with ordered entries. It is a concept-mastery and weakness-review coach grounded in deliberate practice — Ericsson for attempt structure, Bjork for desirable difficulty. The signal is mastery and weakness derived from observed attempts: the coach knows which concepts decayed and which patterns you miss, and steers the next session from that.

The vocabulary splits are load-bearing. A `note` is a private Zettelkasten artifact with its own maturity lifecycle; published `content` is a different table with a different lifecycle. Conflating them breaks the system's guarantees.

## Knowledge retrieval

Any agent queries published content and Zettelkasten notes through MCP via `search_knowledge`, backed by hybrid retrieval: PostgreSQL full-text search (tsvector with websearch syntax, GIN-indexed) and pgvector semantic search (HNSW, cosine) fused per corpus with reciprocal-rank fusion. A background reconciler embeds new contents and notes as they land (`gemini-embedding-2`), so the semantic side stays current without touching any request path; without `GEMINI_API_KEY`, search runs FTS-only.

## The agent toolset

Eleven MCP tools — small on purpose. Everything an agent can do is a workflow step with valid transitions and invariant checks, never raw table access:

| Tool | What it does |
|---|---|
| `brief` | Read-only planning-state pull. `mode=morning` is the daily briefing (overdue / today / committed / upcoming todos, active goals, unverified hypotheses, RSS highlights, content pipeline); `mode=reflection` is the end-of-day plan-vs-actual retrospective. |
| `search_knowledge` | Search across content and notes — the agent's window into what you know. |
| `capture_inbox` | Drop a raw todo into your GTD inbox; you clarify it later. |
| `plan_day` | Set today's plan as one atomic replacement. No auto-carryover. |
| `start_session` / `record_attempt` / `end_session` | Learning-session lifecycle: begin, record attempts + observations, end with a summary. |
| `learning_read` | Read-only learning analytics (`view = overview \| next_target \| attempts \| session_progress`). |
| `manage_plan` | Learning-plan curriculum (`action = add_entries \| remove_entries \| update_entry \| reorder \| progress`). |

`brief` and `learning_read` are read-only; the mutating tools each encapsulate one workflow step with required fields and valid transitions, so the rules live in the tool layer, not in prompt instructions scattered across agents.

## What this enables

**Agents see the same state.** When the planner writes a morning briefing, it reads the same daily plan, open todos, and goal progress any other agent would — there is no "what did I tell the other agent", only the schema.

**Briefings grounded in yesterday.** The planner reads yesterday's daily plan, checks which items completed / deferred / dropped, and shows goal progress against milestones — generated from state, not from your recollection.

**Coaching grounded in evidence.** The learning coach sees that your last three sliding-window attempts produced pattern-recognition failures with moderate severity, and that mastery of the concept declined over two weeks. The coaching is specific because the evidence is — and every observation carries a confidence label that controls whether it counts toward the primary view.

**One audited trail.** Because every mutation writes an `activity_events` row with its actor, the whole system has a single structural history — who changed what, when — that no agent can opt out of.

## Scope and limits

A single-admin system by design: no RBAC, no multi-tenant, no "share with a colleague" — one human, several AI agents. The admin UI is private; only a subset of content (articles, build logs, TILs, the project portfolio) renders on the public site, and only after you explicitly publish it. Goals, attempts, and notes stay private. If you want a team wiki or a Notion clone, this is not it.

## Tech stack

| Layer            | Choice                                                                        |
| ---------------- | ----------------------------------------------------------------------------- |
| Backend          | Go 1.26+ (stdlib-first), PostgreSQL 17, pgx/v5, sqlc                           |
| Search           | Hybrid: PostgreSQL FTS (tsvector + websearch + GIN) + pgvector semantic (HNSW, cosine), RRF-fused; FTS-only without `GEMINI_API_KEY` |
| Embedding        | `gemini-embedding-2` (1536d Matryoshka); background reconciler keeps contents + notes embedded |
| Scheduling       | Agent cadences declared in `internal/agent/registry.go`; execution driven by an external Cowork/Desktop runner; audited via `process_runs` |
| Frontend         | Angular 22 (SSR, zoneless, Signal Forms), Tailwind CSS v4                      |
| AI collaboration | Claude (Cowork + Code), Codex CLI, MCP (11 workflow tools)                    |
| Cache            | Ristretto (in-memory, single machine)                                         |
| Object storage   | Cloudflare R2 (S3-compatible)                                                  |

---

## License

**All Rights Reserved** — see [LICENSE](LICENSE).

This repository is published for portfolio and reference reading only. No permission is granted, express or implied, to use, copy, modify, merge, publish, distribute, sublicense, or sell copies of the software, documentation, or any part of this repository. Viewing on GitHub does not constitute a grant of any rights.

This is a single-admin system by design, not a community project. There is no CONTRIBUTING, SECURITY, or issue-template process, and external contributions are not being accepted. To request permission for a specific use, contact the copyright holder.
