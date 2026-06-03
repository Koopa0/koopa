# `docs/` — index, authority, and what counts as runtime truth

> **Project status (Phase 1D, 2026-05-27):** koopa is a **private portfolio /
> source-visible reference repository**, not open source. See the root
> [README.md](../README.md) and [LICENSE](../LICENSE). The docs below describe
> the system that exists for the single admin and the closed agent set; they
> are not contributor onboarding material.

This index tells a reader (human or agent) **which documents bind behavior
and which are context only**. It does not duplicate content — it points.

## Authority order (canonical statement lives in the contract)

The single source of the authority order is
[`backend-semantic-contract.md`](backend-semantic-contract.md) §2 (Sources of
truth) (higher binds lower — when two disagree, the higher wins and the lower
MUST be updated):

1. **Schema / migrations + DB constraints** — `migrations/*.sql`
2. **Go code + tests** — `internal/`, `cmd/`
3. **MCP ops catalog + tool descriptions** (`internal/mcp/ops/catalog.go`) and **MCP behavior policy** (`.claude/rules/mcp-decision-policy.md`)
4. **Backend semantic contract** — `backend-semantic-contract.md`
5. **Skills / agent operational docs** — `skills/koopa-system/`, `docs/Koopa-*.md`
6. **Historical docs** — `docs/audit/`, `docs/audit-prompts/`

## Document classification

| Document | Tier | Runtime truth? | Notes |
|---|---|---|---|
| `backend-semantic-contract.md` | 4 (canonical) | **Yes** — shared vocabulary + cross-entity contract | 7 sections (§1–§7): core domain vocabulary is §3, domain boundaries §4, MCP tool semantics §5. |
| `LEARNING-CONTRACT.md` | 4 (canonical companion) | **Yes** — FSRS vs concept-mastery split | — |
| `authorization-matrix.md` | 4 (canonical companion) | **Yes** — MCP write-tool authorization | Four-axis model. |
| `audit/*.md` | 6 (historical) | **No** — point-in-time review | Findings reflect repo state at the dated moment; verify before acting. |
| `audit-prompts/*.md` | 6 (historical) | **No** — past audit-session prompts | Session inputs, not contracts. |

Out of `docs/` but in the order: `migrations/*.sql` (tier 1),
`internal/`+`cmd/` (tier 2), `internal/mcp/ops/catalog.go` +
`.claude/rules/mcp-decision-policy.md` (tier 3),
`skills/koopa-system/references/*.md` (tier 5, incl. `tools.md` — the MCP
tool parameter reference, formerly `docs/MCP-TOOLS-v2.md`).

## Proposed drift checks (NOT implemented — proposals only)

These would convert the doc/code drift this index guards against into
automated gates. Listed for a future task; none is wired today.

1. **Doc/path reference existence.** A CI script greps every `docs/…\.md`,
   `migrations/…\.sql`, and `skills/…\.md` path mentioned in `docs/`,
   `.claude/rules/`, `skills/`, and Go comments, and fails if the target
   file does not exist. Catches the `SYSTEM-SEMANTICS.md` /
   `MCP-TOOLS-v2.md` / `narrative-rewrite-scope.md` / `005_bookmarks` class.
2. **Stale test-filename references.** Same idea, scoped to `*_test.go`
   filenames named in comments — assert the referenced test file exists
   (would have caught `store_integration_test.go` / `server_test.go`).
3. **Retired-vocabulary gate.** `forbidigo` (already enabled in
   `.golangci.yml`) configured to reject `flow`, `bookmark_rss`,
   `resolve_directive` as identifiers in new non-test code. (`p0/p1/p2`
   are currently accepted input aliases — see contract §3 (priority) and §7
   Open Question #3; keep-vs-remove is an open decision — so they are NOT in
   this list.)
4. **Search-corpus pin.** A unit test asserting `search_knowledge`'s
   `selectSources` corpus matches a documented constant, so README/corpus
   claims and code cannot silently diverge again.
5. **Bookmark-lifecycle pin.** A doc-test (or a comment-linked assertion)
   that the set of routes under `/api/admin/knowledge/bookmarks` matches
   the bookmark lifecycle documented in contract §3 (create/edit/delete, no
   draft→review; edit-flow intent is §7 Open Question #2).

## Maintenance rule

When a code/schema change makes a doc statement false, update the doc **in
the same commit**. If you cannot yet describe the new truth, add it to
`backend-semantic-contract.md` §7 (Open Questions) rather than leaving a
false statement standing.
