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
> There is no CONTRIBUTING / SECURITY / issue-tracker process — this is a
> single-admin system by design, not a community project.

**koopa** is a private-by-default personal OS where AI agents share a semantic runtime — so the AI reads your state, not your prompts.

It's 8 a.m. You ask HQ for the day. It doesn't ask what's on your plate — it reads yesterday's unfinished daily plan, this week's goal progress, the learning targets your last sessions flagged as weak, and the RSS highlights the ingest pipeline collected overnight, and hands you one briefing. You skim it, set today's plan, and start. Through the day the agents stay in their lane: HQ plans, Learning Studio coaches a practice session, any agent searches the corpus or co-authors a note — all in conversation with you. Nothing high-stakes happens behind your back: every goal, project, milestone, and published article is **your** decision, made in the admin UI. The agents surface structure; you make the call.

## Why this exists

Most AI integrations are stateless: every conversation starts from zero, every agent is a fresh amnesiac, and you spend your time re-explaining context. The more agents you add — Claude Code in your editor, Cowork agents on schedulers, background summarizers — the worse it gets. Each produces output the others never see.

koopa takes a different position: AI understands your work because your work is **structurally modeled**. Goals, projects, todos, learning attempts, daily plans, content drafts, cognitive observations — all first-class entities with precise schemas and their own lifecycles. Every agent reads from and writes to the same semantic store through MCP. When Learning Studio opens a practice session, it already knows which concepts you struggled with last week and which plan you're executing. When HQ assembles your morning briefing, it reads yesterday's daily plan and surfaces what didn't get done — not because you summarized it, but because the state is there.

This is not a chatbot with memory. The AI reads a goal's milestones, its linked projects, its recent activity — queried from a structured schema, shared across every agent. Understanding is precise, not reconstructed.

## How it works

The actor axis is **flow vs. decision**, not human vs. agent:

- **Cowork agents drive flows** through a small MCP toolset, in conversation with you.
- **You are the sole decision-maker _and_ the sole router.** There is no agent→agent dispatch and no agent→agent status channel. Coordination is the shared state in the database, not a message bus.
- **The admin UI is where you confirm, decide, and view** — it owns every high-commitment write.

Functionally the agents are a **planner**, a **learning coach**, a **search window**, and a **note co-author**. They run on declared cadences — HQ at 8 a.m., others on their own schedules pinned in the Go agent registry (`internal/agent/registry.go::BuiltinAgents()`) — but **execution is driven by an external Cowork/Desktop runner, not by this repo**; the backend owns the registry metadata, the schema, and the `process_runs` table that audits each external run.

Identity, not capability tokens, gates writes. Every MCP call self-identifies via an `as` field; the server resolves it against the registry and applies a three-axis authorization (`internal/mcp/authz.go`): an **author** allowlist (a human is always permitted), **registration** (a known, non-anonymous caller), and **self** (you may only act on your own rows). An unknown caller fails closed on every mutating tool.

Two structural invariants are real, not aspirational:

**Publishing is atomic.** Content cannot leak public by accident — `status='published'`, `is_public=true`, and `published_at=now()` are set in one operation, protected by a joint CHECK constraint.

**Every mutation has an actor.** Every write to a covered entity produces an `activity_events` row via AFTER trigger, carrying the agent name that caused it. Application code cannot insert there directly; the audit log is structural, not voluntary.

### Autonomy with a gate

Agents can capture a raw todo to your inbox, draft a note, run a search, recommend the next learning target — useful, low-stakes flows. But **they cannot create high-commitment entities**. Goals, projects, milestones, hypotheses, learning plans, learning domains, and published content are created **only through the admin UI** (authenticated HTTP), by you. The agent surfaces the option in conversation; you commit it.

The design choice underneath: AI can run autonomously _because_ the commitment surface is yours. Without that boundary, autonomy would flood your system with entities you never decided to keep. With it, autonomy is useful — agents surface options, you keep the call. A system that makes decisions for you eventually makes you worse at making them.

## The shared semantic runtime

The system models three bounded contexts. Each has its own vocabulary, its own lifecycle, and non-overlapping definitions:

**Commitment** — PARA + GTD. Areas (ongoing responsibilities), goals (outcomes with optional deadlines), milestones (binary progress checkpoints), projects (execution vehicles), todos (personal GTD items), daily plan items (today's commitments). The daily plan has **no auto-carryover**: yesterday's unfinished work surfaces in the morning briefing but does not roll forward automatically. Confrontation is a feature — auto-carryover erodes your relationship with your own commitments.

**Knowledge** — five first-party content types (`article`, `essay`, `build-log`, `til`, `digest`) with an editorial lifecycle (`draft → review → published → archived`); Zettelkasten notes in a separate table with six sub-kinds (`solve-note`, `concept-note`, `debug-postmortem`, `decision-log`, `reading-note`, `musing`) and a maturity lifecycle (`seed → stub → evergreen → needs_revision → archived`); RSS feeds with scheduled fetch and auto-disable on consecutive failures. Content is authored in the admin UI; agents co-author notes via MCP.

**Learning** — a concept ontology, learning targets (individual problems, chapters, drills), sessions with a declared mode, attempts with an outcome taxonomy, observations with confidence labels, learning plans with ordered entries. This is a **concept-mastery and weakness-review coach** grounded in deliberate practice (Ericsson for attempt structure, Bjork for desirable difficulty) — **not** an Anki-style spaced-repetition product. There is no due-queue and no review scheduler; the signal is mastery and weakness derived from observed attempts.

The vocabulary splits are load-bearing. A `note` is a Zettelkasten knowledge artifact, private to you, with its own maturity lifecycle; it is not the same as published `content`. Conflating them breaks the system's guarantees.

## Knowledge retrieval

Published content and Zettelkasten notes are queryable by any agent through MCP via `search_knowledge`. **Today it runs PostgreSQL full-text search** (tsvector with websearch syntax, GIN-indexed) over content and notes. The pgvector schema, HNSW indexes, and embedder package are in place, but the document-embedding write/backfill pipeline and the reciprocal-rank-fusion merge path are not active yet. The hybrid lexical + semantic + RRF path is **planned**, to be activated once an embedder write/backfill pipeline lands.

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
| `create_note` / `update_note` | Co-author the Zettelkasten — body and links. Maturity is yours to set in the admin UI. |

`brief` and `learning_read` are read-only forever; they never grow a mutation. Everything else high-commitment — goals, projects, milestones, hypotheses, plan activation, content authoring and publishing, note maturity, feed curation — lives in the admin UI, off the agent surface.

## Design philosophy

**AI understands you through structure, not prompts.** Context windows and memory files are the conventional path to personalization. koopa takes the opposite position: AI understands your work because the work is explicitly modeled in a semantic schema that every agent reads the same way. No drift between agents, no "I think you mentioned…" — just the model.

**Your ownership is preserved by design.** Admin-only commitment creation, confidence-labeled observations, no auto-carryover — every friction choice exists to keep you the decision-maker rather than a passive approver of AI suggestions. A system that presents structured information and waits for your call makes you better over time.

**Workflow semantics, not raw database access.** MCP tools expose operations like `brief`, `plan_day`, `record_attempt` — not `SELECT * FROM todos`. Each tool encapsulates a meaningful step with valid transitions, required fields, and invariant checks. Rules live in the tool layer, not in prompt instructions scattered across agents.

## What this enables

**Agents see the same state.** When HQ writes a morning briefing, it reads the same daily plan, the same open todos, the same goal progress that any other agent would. There is no "what did I tell the other agent"; there is only the schema.

**Morning briefings grounded in yesterday.** HQ doesn't ask what you did. It reads yesterday's daily plan, checks which items completed / deferred / dropped, surfaces open todos, shows goal progress against milestones. The briefing is generated from state, not from your recollection.

**Learning coaching grounded in evidence.** Learning Studio doesn't generically suggest "practice more." It sees that your last three attempts at sliding-window targets produced pattern-recognition failures with moderate severity, and that mastery of this concept declined over two weeks. The coaching is specific because the evidence is specific — and every observation carries a confidence label that controls whether it contributes to the primary view or surfaces only under `confidence_filter=all`.

**One audited trail.** Because every mutation writes an `activity_events` row with its actor, the whole system has a single, structural history — who changed what, when — that no agent can opt out of.

## Scope and limits

This is a single-admin system by design. No RBAC, no multi-tenant, no "share with a colleague" — one human, several AI agents. The admin UI is private; only a subset of content (articles, build logs, TILs, the project portfolio) renders on the public site, and only after you explicitly publish it. Goals, attempts, and notes stay private. If you want a team wiki or a Notion clone, this is not it.

## Tech stack

| Layer             | Choice                                                                                                                                       |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend           | Go 1.26+ (stdlib-first), PostgreSQL 17, pgx/v5, sqlc                                                                                         |
| Search (today)    | PostgreSQL FTS (tsvector + websearch + GIN)                                                                                                  |
| Search (planned)  | Hybrid lexical + pgvector HNSW with RRF merge — schema, indexes, and merge code in place; pending an embedder write/backfill pipeline        |
| Embedding         | `gemini-embedding-2-preview` (1536d Matryoshka) target; pgvector columns + HNSW indexes in place; no production write path yet (see Search)  |
| Scheduling        | Agent cadences declared in `internal/agent/registry.go::BuiltinAgents()`; execution driven by an external Cowork/Desktop runner; audited via `process_runs` |
| Frontend          | Angular 22 (SSR, zoneless, Signal Forms), Tailwind CSS v4                                                                                   |
| AI collaboration  | Claude (Cowork + Code), MCP (11 workflow tools)                                                                                             |
| Cache             | Ristretto (in-memory, single machine)                                                                                                       |
| Object storage    | Cloudflare R2 (S3-compatible)                                                                                                                |

---

## License

**All Rights Reserved** — see [LICENSE](LICENSE).

This repository is published for portfolio and reference reading only. No permission is granted, express or implied, to use, copy, modify, merge, publish, distribute, sublicense, or sell copies of the software, documentation, or any part of this repository. Viewing on GitHub does not constitute a grant of any rights.

This is a single-admin system by design, not a community project. There is no CONTRIBUTING, SECURITY, or issue-template process, and external contributions are not being accepted. To request permission for a specific use, contact the copyright holder.
