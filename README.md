<p align="center">
  <img src="frontend/public/logo-title.png" alt="koopa0.dev" width="320">
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
    <img src="https://img.shields.io/badge/pgvector-768d-378ADD?style=flat" alt="pgvector"/>
    <img src="https://img.shields.io/badge/FSRS-spaced_repetition-1D9E75?style=flat" alt="FSRS"/>
  </p>
</p>

A Go backend that turns Notion, Obsidian, and RSS into a unified system — where AI operates as a first-class user through 23 MCP tools.
Not a blog platform. Not another PKM app. This is personal infrastructure — the same system I use every day to plan tasks, track learning, collect and curate articles, and publish what's worth sharing. Multiple AI environments (Claude Web, Claude Code, Cowork) connect to the same Go server and PostgreSQL, coordinating through structured artifacts instead of starting every conversation from scratch.

---

**koopa0.dev** is a personal operating system where AI participants — not just users — are first-class citizens. Multiple Claude instances collaborate inside a shared knowledge system, each with a defined role, capability boundary, and formal communication protocol, to help track goals, manage tasks, guide learning, produce content, and make decisions.

It is not a blog. It is not a to-do app. It is a system that **ingests, processes, and outputs knowledge**, with AI woven into every layer.

<p align="center">
  <img src="docs/images/architecture.svg" width="720" alt="System architecture"/>
</p>

## How it works

Traditional AI integration follows a request-response pattern: you ask, the AI answers. koopa0.dev inverts this. Five AI participants operate within a single knowledge system, coordinating through a formal IPC (Inter-Participant Communication) protocol.

**HQ** is the CEO — it makes decisions, dispatches work, and tracks progress across the organization. **Content Studio** owns content strategy, from topic selection through writing to quality review. **Research Lab** conducts deep analysis and produces structured reports. **Learning Studio** acts as a cognitive coach, applying deliberate practice principles to guide skill development. **Claude Code** serves as the development agent, implementing features and fixing bugs directly in the codebase.

These participants don't just respond to commands. They issue **directives** (prioritized instructions with a full lifecycle: issued → acknowledged → resolved), file **reports** (both in response to directives and self-initiated), write **journal entries** (plans, context snapshots, reflections, metrics), and track **insights** (hypotheses with explicit invalidation conditions). Every interaction follows the protocol — this isn't role-playing, it's an organization with enforceable capability constraints.

## The knowledge lifecycle

Everything in koopa0.dev flows through three stages: input, processing, and output.

<p align="center">
  <img src="docs/images/data-flow.svg" width="720" alt="Knowledge lifecycle"/>
</p>

**Input** captures knowledge from multiple sources. An Obsidian vault syncs notes, LeetCode solutions, and reading annotations. RSS feeds are fetched on schedule with HTTP ETag optimization. Notion syncs projects and goals. GitHub webhooks surface development activity. And every Claude participant contributes tasks, observations, and decisions through MCP.

**Processing** is where raw input becomes structured knowledge. A Genkit-powered AI pipeline classifies, summarizes, and scores content. A tag normalization engine resolves raw tags through aliases into a canonical taxonomy. pgvector embeddings (768 dimensions) power semantic search alongside PostgreSQL full-text search. And a knowledge graph built from wikilinks maps relationships between notes.

**Output** takes multiple forms. A public Angular SSR website presents articles, build logs, TILs, and a project portfolio. A private admin workspace provides dashboards for daily planning, task management, goal tracking, learning analytics, content review, and RSS curation. Every piece of knowledge is also queryable by any AI participant through MCP — the system feeds back into itself.

## Features

### PARA + GTD task and goal management

koopa0.dev fuses two productivity frameworks into a unified system. PARA provides the structural hierarchy — **Areas** (ongoing responsibilities), **Goals** (targeted outcomes with optional deadlines), **Milestones** (binary checkpoints within goals), and **Projects** (short-term efforts with deliverables). GTD provides the execution flow — **Capture** (zero-friction inbox), **Clarify** (promote to actionable todo), **Organize** (assign to projects, link to goals), **Reflect** (morning briefings, weekly reviews), and **Engage** (daily plan commitment).

The **Daily Plan** is not a simple to-do list. Each planned item records who selected it, why, and its position in the priority order. There is no auto-carryover — yesterday's unfinished work surfaces during the morning briefing, but you must consciously decide to defer or drop each item. Forcing you to face incomplete work is a feature, not a bug.

### Learning engine

The deepest module in the system, grounded in cognitive science research (Dunlosky et al. 2013, Ericsson's deliberate practice, Bjork's desirable difficulties).

<p align="center">
  <img src="docs/images/learning-engine.svg" width="720" alt="Learning engine"/>
</p>

A **Concept Ontology** organizes knowledge into a hierarchical tree by domain (LeetCode, Japanese, system design) and kind (pattern, skill, principle). **Learning Items** — individual problems, grammar points, or chapters — exist independently of notes and form their own relationship graph (easier/harder variants, prerequisites, follow-ups).

The core recording model has three layers. A **Session** is a timed learning block with a declared mode (retrieval, practice, mixed, review, reading). Within a session, each **Attempt** records one try at one item — the outcome (solved independently, needed hints, gave up), duration, where you got stuck, and which approach you used. Each attempt generates **Observations** — micro-level cognitive signals linked to specific concepts. An observation is either a weakness (with severity: minor/moderate/critical), an improvement, or a demonstration of mastery.

Observations feed into a confidence-gated pipeline. High-confidence signals (directly evidenced by behavior) are recorded automatically. Low-confidence signals (inferred by AI) require user confirmation before they enter the analysis — keeping the data clean. Eight cognitive weakness types are tracked: pattern recognition failure, constraint analysis weakness, approach selection confusion, state transition confusion, edge case blindness, implementation gap, complexity miscalculation, and loop condition instability.

An FSRS-based spaced repetition engine schedules reviews for both content (article recall) and learning items (problem retention), driven by four-point ratings (Again / Hard / Good / Easy).

### Intelligent RSS

Feeds are managed with scheduling, priority levels, and filter rules. A fetch pipeline uses HTTP ETag and Last-Modified headers for efficiency, with automatic disabling after consecutive failures. An AI relevance scorer computes per-article scores based on keyword weights. A curation workflow moves items through unread → read → curated (promoted to bookmark or article) or ignored. Topic monitors proactively surface new content matching watched subjects.

### Content management and publishing

Seven content types serve different purposes: Article (deep technical writing), Essay (opinion pieces), Build Log (development records), TIL (daily learning), Note (technical notes), Bookmark (recommended resources with commentary), and Digest (weekly roundups). Content moves through a lifecycle (draft → review → published → archived) with AI review tiers ranging from auto-publish for low-risk content to strict human-approval gates.

## MCP tool design

koopa0.dev exposes 23 workflow-driven tools through MCP, organized in five layers.

**Context Suppliers** deliver situational awareness — `morning_context` assembles everything you need to start the day in a single call; `learning_dashboard` surfaces weakness trends, mastery levels, and review schedules; `search_knowledge` provides unified search across all content types.

**Commitment Gateway** enforces the two-step commitment pattern. `propose_commitment` lets AI suggest goals, projects, milestones, directives, insights, or learning plans — but never creates them directly. Only after user confirmation does `commit_proposal` persist the entity. AI doesn't make promises on your behalf.

**Lifecycle Transitions** manage state machines — `advance_work` moves tasks through clarify/start/complete/defer/drop; `plan_day` builds the daily commitment; `manage_plan` handles learning plan operations.

**Direct Recording** captures low-risk data with minimal friction — `capture_inbox` for quick thoughts, `write_journal` for reflections, `start_session` / `record_attempt` / `end_session` for the learning recording pipeline.

**Content Management** handles publishing workflows — `manage_content` for the full content lifecycle and `manage_feeds` for RSS subscription operations.

A key design principle is **Semantic Maturity Assessment**. Before creating any entity, the system evaluates input maturity on a four-level scale (M0 vague → M1 forming → M2 structured → M3 actionable). If you say "I want to get better at English" (M0), the AI stays in conversation to help you crystallize the goal rather than rushing to create a half-baked entity.

## Design philosophy

**AI as collaborator, not tool.** The system is designed around the premise that AI participants are organizational members with defined roles, not chatbots bolted onto a CRUD app. The IPC protocol — directives, reports, journals, insights — exists because coordination requires structure.

**Make difficulty a feature.** No auto-carryover in daily planning. Confidence gates on learning observations. Maturity assessment before entity creation. These friction points are deliberate — they force conscious engagement with your own knowledge system rather than passive accumulation.

**Workflow-oriented, not CRUD.** The MCP interface exposes semantic operations (`morning_context`, `propose_commitment`, `advance_work`) rather than raw database access. Each tool encapsulates a meaningful workflow step, not a table operation.

## Tech stack

| Layer             | Choice                                          |
| ----------------- | ----------------------------------------------- |
| Backend           | Go (stdlib-first), PostgreSQL, pgx/v5, sqlc     |
| AI pipeline       | Genkit (Go), pgvector                           |
| Frontend          | Angular (SSR), Tailwind CSS                     |
| AI collaboration  | Claude (Cowork + Code), MCP                     |
| Spaced repetition | FSRS algorithm                                  |
| Search            | Full-text (tsvector) + Semantic (pgvector 768d) |

---

## License

This repository contains personal content and infrastructure. All rights reserved.
