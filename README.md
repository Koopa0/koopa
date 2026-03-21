# koopa0.dev

<p align="center">
  <img src="frontend/public/logo.png" alt="koopa0.dev" width="120">
</p>

Personal knowledge engine — a system that ingests, processes, and publishes what I learn.

Obsidian is the brain, an AI pipeline is the editorial team, and the website is the publication.

## What this is

koopa0.dev is not a blog. It is a knowledge system with three layers:

- **Input** — Obsidian vault sync, Notion task tracking, RSS feeds, and external data collection
- **Processing** — Go-based AI pipeline that classifies, summarizes, and drafts content with human review gates
- **Output** — Angular SSR website that presents ideas, notes, and project work organized by topic

The value is not in publishing volume. It is in showing how I think, learn, and solve problems.

## Repository structure

```
frontend/     Angular 21 (SSR, Tailwind CSS v4)
backend/      Go API, AI pipeline, data ingestion
docs/         Platform design documents
```

## Content types

| Type | Description |
|------|-------------|
| Article | Long-form technical writing |
| Essay | Non-technical reflection |
| Build log | Project development record |
| TIL | Short daily learning note |
| Note | Technical note fragment |
| Bookmark | Recommended resource with commentary |
| Digest | Weekly or monthly summary |

## Design principles

- **Obsidian-first** — content originates in Obsidian; the website is a presentation layer
- **AI-assisted, human-reviewed** — automated drafting with tiered review (auto / light / standard / strict)
- **Topic-driven** — content is organized by subject, not by format
- **Show the work** — no resume; let projects and writing demonstrate capability
- **Useful to me first** — a knowledge management tool before a public-facing site

## Running locally

See `frontend/CLAUDE.md` and `backend/CLAUDE.md` for development setup and conventions.

## License

This repository contains personal content and infrastructure. All rights reserved.
