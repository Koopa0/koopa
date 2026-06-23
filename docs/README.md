# `docs/` — index, authority, and what counts as runtime truth

> **Project status (2026-06-10):** koopa is a **private portfolio /
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
3. **MCP ops catalog + tool descriptions** (`internal/mcp/ops/catalog.go`) and **authorization** (`internal/mcp/authz.go`, `internal/agent/registry.go`)
4. **Backend semantic contract** — `backend-semantic-contract.md`
5. **Skills / agent operational docs** — `skills/koopa-system/`, each agent's own Cowork project `CLAUDE.md`
6. **Historical docs** — dated audit reports and superseded design docs

## Document classification

| Document | Tier | Runtime truth? | Notes |
|---|---|---|---|
| `backend-semantic-contract.md` | 4 (canonical) | **Yes** — shared vocabulary + cross-entity contract | 7 sections (§1–§7): core domain vocabulary is §3, domain boundaries §4. The MCP tool inventory lives in `internal/mcp/ops/catalog.go::All()` (§5 points there). |
| `audit-prompts/*.md` | 5 (operational) | **No** — executable prompt templates | Stage prompts for the adversarial-review protocol (`.claude/rules/adversarial-review.md`); templates, not contracts. |

MCP write-tool authorization is identity-based (platform / author / self), enforced in code at `internal/mcp/authz.go` (roster: `internal/agent/registry.go`).

Out of `docs/` but in the order: `migrations/*.sql` (tier 1),
`internal/`+`cmd/` (tier 2), `internal/mcp/ops/catalog.go` +
`internal/mcp/authz.go` (tier 3),
`skills/koopa-system/references/*.md` (tier 5, incl. `tools.md` — the MCP
tool parameter reference).

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
3. **Vocabulary-discipline gate.** `forbidigo` (already enabled in
   `.golangci.yml`) configured to keep a fixed list of off-vocabulary
   identifiers out of new non-test code. (`p0/p1/p2` are currently accepted
   input aliases — see contract §3 (priority) and §7 Open Question #2;
   keep-vs-remove is an open decision — so they are NOT in this list.)
4. **Search-corpus pin.** A unit test asserting `search_knowledge`'s
   `selectSources` corpus matches a documented constant, so README/corpus
   claims and code cannot silently diverge again.

## Maintenance rule

When a code/schema change makes a doc statement false, update the doc **in
the same commit**. If you cannot yet describe the new truth, add it to
`backend-semantic-contract.md` §7 (Open Questions) rather than leaving a
false statement standing.
