# IPC Caller Authentication — Design Record

**Date**: 2026-04-05
**Status**: Approved (simplified design)
**Author**: Koopa (owner), Claude Code (Opus 4.6)
**Scope**: Caller identity verification for IPC protocol

---

## 1. Problem Statement

`mcp.koopa0.dev` is a public-facing MCP server. IPC tool calls (`save_session_note`, future `create_directive` / `create_report`) accept a `source` parameter that identifies the calling participant. **This parameter is self-declared and unvalidated.**

Current code (`internal/mcp/write.go:855`):
```go
// Accepts ANY string for source. No verification.
s.sessions.CreateNote(ctx, &session.CreateParams{Source: input.Source, ...})
```

Anyone with a valid Bearer token can write IPC records as any participant, including those with elevated capabilities.

---

## 2. Why Transport-Layer Identity Doesn't Work

An earlier design iteration attempted to solve this by binding platform identity to OAuth tokens — identifying "this connection is from claude-cowork" vs "this connection is from claude-code" at the transport layer. This was rejected for three reasons.

### MCP protocol has no project identity

The MCP `initialize` handshake carries `clientInfo.name` (e.g., "Claude Desktop"), but this identifies the **application**, not the **project**. Claude Desktop's HQ project and Content Studio project both send `clientInfo.name = "Claude Desktop"`. There is no way to distinguish them at the protocol level.

### Anthropic infrastructure obscures the caller

Remote MCP connections (Claude Desktop Connector, claude.ai) are proxied through Anthropic's cloud. Your server receives HTTP requests from Anthropic's IP ranges with a Bearer token. The token proves "Koopa authorized this connection" but carries no information about which Claude project triggered the tool call — because that's an Anthropic product concept, not an MCP protocol concept.

### OAuth clients don't map to participants

Dynamic Client Registration issues one `client_id` per MCP Connector. But Connectors are app-level (one per Claude Desktop installation), not project-level. Multiple Cowork projects share one Connector and one `client_id`. There is no 1:1 mapping from OAuth client to participant.

**Conclusion**: Transport-layer identity verification is impossible with the information available. JWT platform binding, per-platform tokens, platform selection pages, and `--platform` flags are all solving a problem that can't be solved at this layer.

---

## 3. The Actual Trust Model

### Who can call your MCP server?

Only connections authenticated by your OAuth flow (Google login, ADMIN_EMAIL restriction) or static MCP_TOKEN. All callers are **your own Claude instances** — you started them, you logged in, you configured them.

### Where does participant identity come from?

Each Claude project's **system prompt** declares its identity: "You are hq. When calling IPC tools, use `source='hq'`." The prompt layer is the identity binding — not the transport layer.

HQ's prompt says it's hq → it fills `source="hq"`. Content Studio's prompt says it's content-studio → it fills `source="content-studio"`. This is convention, not cryptography, but it's sufficient when all callers are your own instances.

### What's the actual risk?

| Threat | Realistic? | Mitigation |
|--------|-----------|------------|
| External attacker spoofs source | Only if they have a valid token (= token leakage, separate problem) | OAuth + MCP_TOKEN |
| Claude instance prompt-injected to use wrong source | Possible but unlikely in practice | Capability flags limit blast radius |
| Koopa accidentally uses wrong source in manual operation | Low frequency, self-correcting | Error message lists valid participants |

### What needs to be verified

Only two things, at the tool call level:

1. **`source` is a valid participant** — it exists in the `participant` table
2. **`source` has the required capability** — the relevant boolean flag is true

One DB query. No JWT, no platform binding, no connection state.

---

## 4. Design

### 4.1 Participant store

New package: `internal/participant/`

```
internal/participant/
  participant.go   — Participant type, sentinel errors
  store.go         — DB operations
  query.sql        — sqlc queries
```

Key operations:
- `Participant(ctx, name) (*Participant, error)` — single lookup by PK
- `ParticipantsByPlatform(ctx, platform) ([]Participant, error)` — list for admin
- `CreateParticipant(ctx, params) (*Participant, error)` — admin creation
- `UpdateCapabilities(ctx, name, caps) error` — toggle flags

### 4.2 IPC validation

Every IPC write tool adds this at the top:

```go
p, err := s.participants.Participant(ctx, input.Source)
if err != nil {
    return toolError("unknown participant: %s", input.Source)
}
if !p.CanIssueDirectives {  // or the relevant capability for this tool
    return toolError("participant %s cannot issue directives", input.Source)
}
```

Capability mapping per tool:

| Tool | Required capability |
|------|-------------------|
| `create_directive` | `can_issue_directives` |
| `create_report` / `save_session_note(kind=report)` | `can_write_reports` |
| `save_session_note(kind=plan/reflection/context/metrics)` | participant exists (any) |
| `save_session_note(kind=insight)` | participant exists (any) |
| `create_task` | `task_assignable` (for `assignee` param) |

### 4.3 MCP admin tools

Participant management through MCP conversation:

| Tool | Purpose | Auth gate |
|------|---------|-----------|
| `register_participant` | Create participant + set capabilities | `source` must be `human` |
| `update_participant` | Modify capabilities, description | `source` must be `human` |
| `list_participants` | View all participants + capabilities | Any valid source |
| `deactivate_participant` | Set all capability flags to false | `source` must be `human` |

Write tools are gated by `source = "human"` — only direct human operation can modify the participant registry. This prevents an AI session from escalating its own capabilities.

### 4.4 New participant onboarding

```
Step 1: Register participant (one-time)
  → MCP tool: register_participant(name="side-project", platform="claude-code",
      task_assignable=true, can_write_reports=true)
  → Or SQL: INSERT INTO participant (name, platform, ...) VALUES (...)

Step 2: Configure Claude project system prompt
  → "You are side-project. Use source='side-project' in IPC tool calls."

Step 3: Done. No tokens, no config, no server restart.
```

### 4.5 What `platform` column is for

`platform` is **classification and query**, not authentication.

Used for:
- "List all participants on claude-cowork" (admin view)
- "Which participants should appear in morning briefing?" (filter by platform capabilities)
- "What execution environment does this participant run in?" (operational context)

Not used for:
- ~~Verifying that a connection belongs to a platform~~
- ~~Token-to-platform binding~~
- ~~Transport-layer identity~~

---

## 5. What NOT to Build

| Rejected approach | Why |
|-------------------|-----|
| Per-platform OAuth tokens | MCP protocol doesn't carry project identity |
| Platform selection page after Google login | Anthropic proxies connections — platform is unknowable |
| `--platform` flag for stdio mode | Unnecessary if source is validated at tool-call level |
| JWT claims with platform identity | Over-engineering for single-owner system |
| Per-platform static tokens | Adds config complexity without security benefit |
| Connection-level platform caching | MCP sessions don't map 1:1 to participants |

---

## 6. When This Design Becomes Insufficient

This trust model depends on: **all callers are Koopa's own Claude instances.**

If any of these conditions become true, revisit the design:

| Condition | What breaks | What to add |
|-----------|------------|-------------|
| MCP server accepts connections from other users | `source` can be spoofed by untrusted callers | Per-user authentication + participant ownership |
| Third-party integrations call IPC tools | Can't trust system prompt conventions | Signed tokens with participant claims |
| Multi-tenant / open-source deployment | Multiple owners, competing interests | Full RBAC, tenant isolation |

Until then, capability flags + participant existence check is sufficient.

---

## 7. Implementation Plan

### Phase 1: Participant store (foundation)

New `internal/participant/` package. sqlc queries against existing `platform` + `participant` tables. No schema changes.

### Phase 2: IPC tool hardening

Add participant validation to every IPC write tool:
- `save_session_note` — validate source exists + capability by kind
- Future `create_directive` — validate source.can_issue_directives
- Future `create_report` — validate source.can_write_reports
- `create_task` — validate assignee.task_assignable

### Phase 3: MCP admin tools

`register_participant`, `update_participant`, `list_participants`, `deactivate_participant`. Gated by `source = "human"`.

### No Phase 4+

No OAuth changes, no transport changes, no token changes. The existing `mcpauth.go` is correct for what it does (connection-level auth). It just doesn't need to do more.

---

## 8. Schema Impact

**None.** The `platform` and `participant` tables already exist with the correct structure. All capability flags are in place. `ON DELETE RESTRICT` prevents accidental participant deletion.

---

## 9. Cross-References

| Document | Relevance |
|----------|-----------|
| `migrations/001_initial.up.sql` lines 62-108 | `platform` + `participant` schema + seed data |
| `internal/mcpauth/mcpauth.go` | Connection-level auth (unchanged) |
| `internal/mcp/write.go:855-905` | `saveSessionNote` — current IPC write path (needs validation) |
| `internal/mcp/search.go:1009-1026` | Source whitelist for reads (reference for valid sources) |
| `docs/PARTICIPANT-CAPABILITIES-AND-SCHEDULES.md` | Capability flag semantics |
| MCP spec 2025-11-25 — `initialize` | `clientInfo` carries app name, not project identity |

---

## 10. Design Review Log

**v1 (2026-04-05, rejected)**: OAuth platform binding — per-platform tokens, platform selection page, `--platform` flag, 3-step validation with binding step. Rejected because MCP protocol doesn't carry project-level identity, making transport-layer platform verification impossible.

**v2 (2026-04-05, approved)**: Simplified to source validation + capability check at tool-call level. Trust model: all callers are owner's instances, identity comes from system prompt convention.
