# Hermes — vault curation and the promotion convention

Hermes is the `claude-code` scheduled assistant (`internal/agent/registry.go`).
Its standing job is to organize Koopa's personal Obsidian vault on assigned
cron jobs. As a registered caller it may write notes into koopa0.dev through
`create_note` — but doing so crosses a boundary that this document fixes.

## Two systems share one vault

The Obsidian vault is the source for **two** unrelated pipelines:

- **Whetstone** (`~/go/src/github.com/koopa0/learning`) publishes structured
  course lessons from the vault via its `sync-vault` tool, gated on
  `status: ready`. Course content is Whetstone's domain.
- **koopa0.dev** is the personal blog + knowledge engine. Its `note` corpus is
  Zettelkasten — private knowledge, not course material.

These pipelines never exchange content. A lesson is not a note; a note is not
a lesson.

## The hard boundary

**Hermes never promotes Whetstone course material into koopa0.dev.** Anything
that is (or is becoming) a Whetstone lesson — vault notes under the course
content structure, anything carrying the lesson `status`/`meta` front matter
the `sync-vault` contract reads — stays in the vault for Whetstone. Hermes
only ever promotes *personal knowledge* notes: a solved problem, a concept
worked out, a reading reflection, a decision rationale — the kind of thing
that belongs in a personal Zettelkasten, not a curriculum.

If a vault note's nature is ambiguous, hermes does **not** promote it; it
surfaces the candidate for Koopa to decide. Silence is the safe default.

## The promotion flow

When a cron job turns up a genuine personal-knowledge note worth keeping in
koopa0.dev:

1. **Dedup first.** `search_knowledge` for the note's subject. If the corpus
   already holds it, do not create a duplicate — at most note the overlap for
   Koopa.
2. **Create a draft.** `create_note` with the body and links; pick `kind` from
   the content (`solve-note` / `concept-note` / `reading-note` / `decision-log`
   / `debug-postmortem` / `musing`). Maturity is **not** set here — the server
   defaults it to `seed`, and maturity transitions are Koopa's call in admin.
3. **Koopa reviews.** Drafts created by hermes carry `created_by = hermes`.
   Koopa filters the admin notes list by that author, reads the seeds, and
   decides what matures and what is deleted. Hermes proposes; Koopa keeps.

This is conversation-and-cron-derived capture into an inert seed, not
authorship of standing knowledge: an agent may prepare material, but what
counts as kept knowledge is the owner's stamp.

## Future

The intended end state for hermes is a Telegram bridge (capture and status
from the phone). Not yet wired; the vault-curation cron is the current job.
