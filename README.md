<p align="center">
  <img src="frontend/public/koopa.png" alt="koopa" width="320">
</p>

<p align="center">
  <strong>English</strong> | <a href="README.zh-TW.md">繁體中文</a>
</p>

<p align="center">
  <p align="center">
    <img src="https://img.shields.io/badge/Go-00ADD8?style=flat&logo=go&logoColor=white" alt="Go"/>
    <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
    <img src="https://img.shields.io/badge/Angular-DD0031?style=flat&logo=angular&logoColor=white" alt="Angular"/>
    <img src="https://img.shields.io/badge/MCP-Claude-7F77DD?style=flat" alt="MCP"/>
    <img src="https://img.shields.io/badge/pgvector-1536d-378ADD?style=flat" alt="pgvector"/>
    <img src="https://img.shields.io/badge/FSRS-spaced_repetition-1D9E75?style=flat" alt="FSRS"/>
  </p>
</p>

**koopa** is a private-by-default personal OS where multiple AI agents share a semantic runtime — so the AI reads your state, not your prompts.

It's 8 a.m. Studio HQ writes today's briefing by reading yesterday's unfinished daily plan, this week's goal progress, overdue learning-target reviews, and the RSS highlights the ingest pipeline scored overnight. You haven't typed a word yet. At 2 p.m. Content Studio checks the content pipeline — drafts ready for review, topics without coverage, articles aging without refresh — and files a report if something needs your attention. Each agent runs on its own cron, each produces durable artifacts, and every mutation is attributed to the agent that made it. You wake up, read the briefings, decide what to act on, and reject what you don't want. The system does not decide for you. It gives you structure to decide faster.

## Why this exists

Most AI integrations are stateless: every conversation starts from zero, every agent is a fresh amnesiac, and the human spends their time re-explaining context. The more agents you add — Claude Code in your editor, Cowork agents on schedulers, background summarizers — the worse this gets. Each one produces output the others never see, creating a pile of disconnected reports that nobody reads.

koopa takes a different position: AI understands your work because your work is **structurally modeled**. Goals, projects, todos, learning attempts, daily plans, content drafts, cognitive observations — all first-class entities with precise schemas and their own lifecycles. Every agent reads from and writes to the same semantic store through MCP. When Learning Studio opens a practice session, it already knows which concepts you struggled with last week, which learning targets are overdue for spaced review, and which plan you're executing. When HQ assembles your morning briefing, it reads yesterday's daily plan and surfaces what didn't get done — not because you summarized it, but because the state is there.

This is not a chatbot with memory. The AI reads a goal's milestones, its linked projects, its recent activity — queried from a structured schema, shared across every agent. Understanding is precise, not reconstructed.

## How it works

Five operational agents coordinate through a formal inter-agent protocol:

**HQ** is the CEO — decisions, delegation, morning briefings. **Content Studio** owns the content pipeline from topic selection to publication. **Research Lab** runs deep analysis and produces structured reports. **Learning Studio** is a cognitive coach applying deliberate-practice principles. **Claude Code** is the development agent, implementing features and fixing bugs directly in the codebase.

Each agent holds capability flags that the server checks at compile time via a Go wrapper — you cannot call a mutation method without proof the caller has the matching capability. The capability set is small: `SubmitTasks`, `ReceiveTasks`, `PublishArtifacts`. HQ can submit tasks but not receive them. Learning Studio can receive and publish but not submit. The registry is a Go literal reconciled into the database at startup; adding an agent is one code change and a restart.

Three structural invariants make the system's guarantees real, not aspirational:

**Completion requires output.** A task cannot enter `completed` without at least one response message _and_ at least one artifact — enforced by a database trigger, not a convention. When a task is completed, the artifact exists.

**Publishing is atomic.** Content cannot leak public by accident — `status='published'`, `is_public=true`, and `published_at=now()` are set in one operation, protected by a joint CHECK constraint.

**Every mutation has an actor.** Every write to a covered entity produces an `activity_events` row via AFTER trigger, carrying the agent name that caused it. Application code cannot insert here directly; the audit log is structural, not voluntary.

### Autonomy with a gate

Agents run on their own schedules — HQ at 8 a.m., Content Studio at 2 p.m., Research Lab on industry scans. They can propose goals, suggest projects, submit tasks to each other. But **they cannot directly create high-commitment entities**. Goals, projects, milestones, hypotheses, learning plans, directives — all go through a two-step `propose_commitment` → `commit_proposal` sequence with a signed token. The agent drafts; you confirm. Ownership of your agenda stays with you.

The design choice underneath: AI can run autonomously _because_ there is a proposal gate. Without the gate, autonomy would flood your system with entities you never decided to commit to. With the gate, autonomy is useful — agents surface options, you keep the call.

## The shared semantic runtime

The system models four bounded contexts. Each has its own vocabulary, its own lifecycle, and non-overlapping definitions with the others:

**Commitment** — PARA + GTD. Areas (ongoing responsibilities), goals (outcomes with optional deadlines), milestones (binary progress checkpoints), projects (execution vehicles), todos (personal GTD items), daily plan items (today's commitments). The daily plan has **no auto-carryover**: yesterday's unfinished work surfaces in the morning briefing but does not roll forward automatically. Confrontation is a feature — auto-carryover erodes your relationship with your own commitments.

**Knowledge** — five first-party content types (`article`, `essay`, `build-log`, `til`, `digest`) with an editorial lifecycle (`draft → review → published → archived`); Zettelkasten notes in a separate table with six sub-kinds (`solve-note`, `concept-note`, `debug-postmortem`, `decision-log`, `reading-note`, `musing`) and a maturity lifecycle (`seed → stub → evergreen → needs_revision → archived`); bookmarks as external URLs with commentary; RSS feeds with scheduled fetch and auto-disable on consecutive failures.

**Learning** — a concept ontology, learning targets (individual problems, chapters, drills), sessions with declared mode, attempts with outcome taxonomy, observations with confidence labels, learning plans with ordered entries. The deepest piece in the system, grounded in deliberate-practice and spaced-repetition research (FSRS algorithm for review scheduling, Ericsson for attempt structure, Bjork for desirable difficulty).

**Coordination** — agents, tasks, task messages, artifacts, agent notes. The task lifecycle is `submitted → working → completed | canceled`, plus a revision cycle. `agent_notes` are self-directed narrative (plans, context snapshots, reflections) — they are _not_ a message channel between agents. If Research Lab wants to communicate reasoning to HQ, it goes in a `task_message`, not a note.

The vocabulary splits are load-bearing. `task` is inter-agent work; `todo` is personal GTD. `agent_note` is private memory; `note` is a Zettelkasten knowledge artifact. Conflating them breaks the system's guarantees.

## Knowledge retrieval

Every piece of knowledge is queryable by any agent through MCP. `search_knowledge` runs **hybrid retrieval** — PostgreSQL full-text search (tsvector with websearch syntax, GIN-indexed) _and_ pgvector semantic search (1536-dimension `gemini-embedding-2-preview` via Matryoshka truncation, HNSW-indexed) — and merges results with reciprocal rank fusion. Agents find content that matches by keyword _and_ content that matches by meaning, without choosing a strategy.

Agent notes are keyword-searchable by kind, author, date range, and full-text query. Cross-session context is recoverable: "find what I wrote about embedding pipelines in the last month" is a tool call, not a scroll through a log.

## Design philosophy

**AI understands you through structure, not prompts.** Context windows and memory files are the conventional path to personalization. koopa takes the opposite position: AI understands your work because the work is explicitly modeled in a semantic schema that every agent reads the same way. No drift between agents, no "I think you mentioned…" — just the model.

**Your ownership is preserved by design.** Proposal-first commitments, confidence-labeled observations, no auto-carryover, maturity assessment before entity creation — every friction choice exists to keep you as the decision-maker rather than a passive approver of AI suggestions. A system that makes decisions for you eventually makes you worse at making them. A system that presents structured information and waits for your call makes you better over time.

**Workflow semantics, not raw database access.** MCP tools expose operations like `morning_context`, `advance_work`, `record_attempt` — not `SELECT * FROM todos`. Each tool encapsulates a meaningful workflow step with valid transitions, required fields, invariant checks. Rules live in the tool layer, not in prompt instructions scattered across agents.

## What this enables

Four capabilities that a stateless chatbot cannot offer, two from each axis:

**Agents see the same state.** When HQ writes a morning briefing at 8 a.m., it reads the same daily_plan, the same open todos, the same goal progress that Content Studio saw at 2 p.m. the day before. There is no "what did I tell the other agent"; there is only the schema.

**Scheduler-driven agents compose.** Research Lab's overnight industry scan writes a `tasks` row with an artifact; Content Studio reads it the next afternoon and suggests an article topic; HQ surfaces the suggestion in your morning briefing. Each agent ran independently on its own cron — the coordination is the shared state, not a message bus.

**Morning briefings grounded in yesterday.** HQ doesn't ask what you did. It reads yesterday's daily plan, checks which items completed / deferred / dropped, surfaces open todos, shows goal progress against milestones. The briefing is generated from state, not from your recollection.

**Learning coaching grounded in evidence.** Learning Studio doesn't generically suggest "practice more". It sees that your last three attempts at sliding-window targets produced pattern-recognition failures with moderate severity, that mastery of this concept declined over two weeks, that two targets are overdue for spaced review. The coaching is specific because the evidence is specific — and every observation is labeled with a confidence that controls whether it contributes to the primary view or surfaces only under `confidence_filter=all`.

## Scope and limits

This is a single-admin system by design. No RBAC, no multi-tenant, no "share with a colleague" — one human, many AI agents. The admin UI is private; only a subset of content (articles, build logs, TILs, project portfolio) renders on the public site, and only after the human explicitly publishes it. Tasks, goals, attempts, agent notes stay private forever. If you want a team wiki or a Notion clone, this is not it.

## Tech stack

| Layer             | Choice                                                     |
| ----------------- | ---------------------------------------------------------- |
| Backend           | Go 1.26+ (stdlib-first), PostgreSQL 17, pgx/v5, sqlc       |
| Embedding         | `gemini-embedding-2-preview` (1536d Matryoshka) + pgvector |
| Search            | Hybrid (tsvector websearch + pgvector HNSW, RRF merge)     |
| Frontend          | Angular 21 (SSR), Tailwind CSS v4                          |
| AI collaboration  | Claude (Cowork + Code), MCP (more than 30 workflow tools)  |
| Spaced repetition | FSRS algorithm (short-term steps disabled)                 |
| Cache             | Ristretto (in-memory, single machine)                      |
| Object storage    | Cloudflare R2 (S3-compatible)                              |

---

## License

This repository contains personal content and infrastructure. All rights reserved.
