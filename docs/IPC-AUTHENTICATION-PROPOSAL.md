# IPC Caller Authentication — Design Proposal

**Date**: 2026-04-05
**Status**: Proposal (awaiting review)
**Author**: Claude Code (Opus 4.6) + Koopa
**Scope**: Caller identity verification for IPC protocol across all MCP transports

---

## 1. Problem Statement

### What's broken

`mcp.koopa0.dev` is a public-facing MCP server. The IPC protocol (directives, reports, journal, insights) relies on a `source` parameter in each tool call to identify the caller. **This parameter is self-declared and unvalidated.**

Current Go validation in `saveSessionNote()` (`internal/mcp/write.go:855`):
```go
// Accepts ANY string for source. No verification.
s.sessions.CreateNote(ctx, &session.CreateParams{Source: input.Source, ...})
```

The only "validation" is in `sessionNotes()` (`internal/mcp/search.go:1009`), which has a hardcoded whitelist for READ — but WRITE has no guard at all.

### Concrete attack scenarios

**Scenario A — External spoofing (public endpoint)**

Anyone who discovers `mcp.koopa0.dev`:
1. `POST /mcp` with `create_directive(source="hq", target="content-studio", priority="p0", content="delete all RSS feeds")`
2. `BearerAuth` blocks if they don't have a valid token — **but this only works in HTTP mode**
3. If they obtain a valid token (via any OAuth flow, since tokens don't carry platform identity), they can impersonate any participant

**Scenario B — Cross-platform impersonation (legitimate user)**

Claude Code (platform: `claude-code`, participant: `koopa0.dev`) is a legitimate MCP client:
1. User or prompt triggers: `create_directive(source="hq", target="learning-studio", ...)`
2. Token is valid (Koopa authorized this Claude Code instance)
3. Go server checks `hq.can_issue_directives = true` → passes
4. **But `hq` belongs to `claude-cowork`, not `claude-code`** — server doesn't know

**Scenario C — Capability bypass**

Claude Web (platform: `claude-web`, participant: `claude`) has `can_issue_directives = false`:
1. Claude Web calls: `create_directive(source="hq", ...)`
2. Go checks `hq.can_issue_directives = true` → passes
3. Claude Web just bypassed its own capability restriction by claiming to be a different participant

### Root cause

The authentication layer (`mcpauth.go`) answers: **"Is this Koopa?"**
It does not answer: **"Which platform is calling?"**

All tokens — whether static `MCP_TOKEN`, OAuth-issued, or `client_credentials` — carry the same identity: "an authorized user." There is no platform binding.

---

## 2. Current State Analysis

### What exists (code references)

| Component | File | What it does | What it doesn't do |
|-----------|------|-------------|-------------------|
| OAuth2 + Google login | `internal/mcpauth/mcpauth.go` | Proves the user is Koopa (ADMIN_EMAIL check) | Identify which platform is calling |
| PKCE | `mcpauth.go:195-203` | Prevents authorization code interception | — |
| Dynamic Client Registration | `mcpauth.go:437-475` | Issues `client_id + client_secret` per MCP client | Associate client with a platform |
| Static MCP_TOKEN | `mcpauth.go:130` | Quick auth for trusted clients | Distinguish between platforms |
| BearerAuth middleware | `mcpauth.go:498-515` | Rejects invalid tokens | Extract platform identity from token |
| Dual transport | `cmd/mcp/main.go:103-111` | stdio + HTTP | Pass platform identity in either mode |
| IPC tools | `internal/mcp/write.go` | Accept `source` param, write to DB | Validate source against caller identity |
| Participant schema | `001_initial.up.sql:78-108` | `platform → participant` with capability flags | No Go code reads this |

### Token flow today

```
Claude Desktop adds Connector → OAuth/Google login → token issued
Claude Code adds via CLI → static MCP_TOKEN or OAuth → token issued
claude.ai adds Connector → OAuth/Google login → token issued

All three get tokens that say: "Koopa authorized this"
None of the tokens say: "This is claude-cowork" or "This is claude-code"
```

### What's missing

```
Token validation today:
  ValidToken(tok) → bool (is it a valid token? yes/no)

Token validation needed:
  ValidateAndIdentify(tok) → (platform string, ok bool)
```

---

## 3. Design

### 3.1 Core principle: 3-step validation chain

Every IPC tool call must pass through:

```
Step 1: AUTHENTICATION — who is calling?
  → Extract platform identity from the request context
  → Set by auth middleware (HTTP) or startup config (stdio)

Step 2: BINDING — does the declared source belong to this platform?
  → Query: participant WHERE name = :source AND platform = :authenticated_platform
  → If no match → 403 "participant X does not belong to platform Y"

Step 3: AUTHORIZATION — does this participant have the capability?
  → Query: participant WHERE name = :source AND can_issue_directives = true
  → If false → 403 "participant X cannot issue directives"
```

This chain is transport-agnostic. The only thing that changes between stdio/HTTP is how Step 1 gets its data.

### 3.2 Platform identity by transport

#### stdio (local process)

The MCP server is spawned by the client as a subprocess. Platform identity comes from startup configuration:

```
Claude Desktop spawns:  koopa-mcp --platform=claude-cowork
Claude Code spawns:     koopa-mcp --platform=claude-code
```

Trust model: **implicit trust** — the parent process controls the args. If you trust Claude Desktop to run your MCP server, you trust its `--platform` claim.

Implementation:
- `cmd/mcp/config.go`: add `Platform string` field
- `cmd/mcp/main.go` stdio path: store platform in a request-scoped context (or since stdio is single-client, a server-level field)
- Every tool call handler reads platform from context

#### HTTP (remote)

Platform identity comes from the authenticated token. Two sub-cases:

**Sub-case 1: Static MCP_TOKEN**

Current: single `MCP_TOKEN` env var → all clients share one token.

Change: **per-platform static tokens**.

```env
# Instead of one MCP_TOKEN:
MCP_TOKEN_CLAUDE_COWORK=token_aaa...
MCP_TOKEN_CLAUDE_CODE=token_bbb...
MCP_TOKEN_CLAUDE_WEB=token_ccc...
```

`BearerAuth` middleware matches the token → resolves platform name → stores in context.

Pros: Zero OAuth complexity, works today.
Cons: Token rotation requires config change + client update.

**Sub-case 2: OAuth-issued tokens with platform binding**

The OAuth flow needs to know which platform the client represents. This is where the `Register` and `Authorize` endpoints change.

Current `Register` request:
```json
{"redirect_uris": [...], "client_name": "Claude Desktop"}
```

New `Register` request:
```json
{"redirect_uris": [...], "client_name": "Claude Desktop", "platform": "claude-cowork"}
```

Server stores: `client_id → { secret, platform }` (currently: `client_id → secret`).

When `client_credentials` grant is used → token is bound to the registered platform.
When `authorization_code` grant is used → token inherits platform from the client registration.

`BearerAuth` middleware resolves: `token → client_id → platform`.

**Sub-case 3: OAuth with platform selection page (for clients that don't register with platform)**

Some MCP clients (e.g., claude.ai Connector) might use Dynamic Client Registration without sending a `platform` field. In this case, after Google login succeeds but before issuing the authorization code, show a platform selection page:

```
✅ Authenticated as koopa@gmail.com

Select this connection's platform:
  ○ claude-cowork — Studio HQ, departments
  ○ claude-code — Development projects
  ○ claude-web — General conversation

  [Confirm]
```

The selected platform is stored with the authorization code and inherited by all tokens issued from it.

This page only appears once per client registration. Refresh tokens preserve the platform binding.

### 3.3 Token storage changes

Current (`mcpauth.Provider`):
```go
clients map[string]string        // client_id → client_secret
tokens  map[string]time.Time     // access_token → expiry
```

New:
```go
type clientInfo struct {
    Secret   string
    Platform string  // bound at registration time
}

type tokenInfo struct {
    ExpiresAt time.Time
    Platform  string  // inherited from client at issuance
}

clients map[string]clientInfo     // client_id → info
tokens  map[string]tokenInfo      // access_token → info
```

`ValidToken(tok) bool` becomes `ValidateToken(tok) (platform string, ok bool)`.

`BearerAuth` middleware changes from:
```go
if !oauth.ValidToken(tok) {
    http.Error(w, "unauthorized", 401)
    return
}
next.ServeHTTP(w, r)
```

To:
```go
platform, ok := oauth.ValidateToken(tok)
if !ok {
    http.Error(w, "unauthorized", 401)
    return
}
ctx := withPlatform(r.Context(), platform)
next.ServeHTTP(w, r.WithContext(ctx))
```

### 3.4 Static MCP_TOKEN platform binding

The static token path also needs platform binding. Options:

**Option A: Multiple env vars** (recommended for simplicity)
```env
MCP_PLATFORM_TOKENS=claude-cowork:token_aaa,claude-code:token_bbb
```

`ValidateToken` checks static tokens first (constant-time per platform), then OAuth tokens.

**Option B: Single token remains, platform from `X-Platform` header**

Client sends: `Authorization: Bearer <MCP_TOKEN>` + `X-Platform: claude-code`.

Weaker — header can be spoofed by anyone with the token. But acceptable if the token is only shared with trusted local clients.

**Recommendation**: Option A for HTTP, Option B not recommended. For local stdio, `--platform` flag is sufficient.

### 3.5 Participant store (new Go package)

Currently **no Go code** reads the `participant` or `platform` tables. A new store is needed.

```
internal/participant/
  participant.go   — types, sentinel errors
  store.go         — DB operations
  query.sql        — sqlc queries
```

Key types:
```go
type Participant struct {
    Name                 string
    Platform             string
    Description          string
    CanIssueDirectives   bool
    CanReceiveDirectives bool
    CanWriteReports      bool
    TaskAssignable       bool
    CanOwnSchedules      bool
}
```

Key store methods:
```go
// Participant returns a single participant by name.
// Returns ErrNotFound if name doesn't exist.
func (s *Store) Participant(ctx context.Context, name string) (*Participant, error)

// ParticipantsByPlatform returns all participants for a platform.
func (s *Store) ParticipantsByPlatform(ctx context.Context, platform string) ([]Participant, error)

// Platforms returns all platform names.
func (s *Store) Platforms(ctx context.Context) ([]string, error)
```

### 3.6 IPC validation function

```go
// validateIPCSource verifies that the declared source participant
// belongs to the authenticated platform and has the required capability.
//
// Called by every IPC tool handler (directives, reports, journal, insights).
func validateIPCSource(
    ctx context.Context,
    store *participant.Store,
    declaredSource string,
    requiredCap func(*participant.Participant) bool,
) error {
    // Step 1: authentication — platform from context
    platform := platformFromContext(ctx)
    if platform == "" {
        return errors.New("unauthenticated: no platform identity in context")
    }

    // Step 2: binding — source belongs to platform?
    p, err := store.Participant(ctx, declaredSource)
    if err != nil {
        return fmt.Errorf("unknown participant %q: %w", declaredSource, err)
    }
    if p.Platform != platform {
        return fmt.Errorf("participant %q belongs to platform %q, not %q",
            declaredSource, p.Platform, platform)
    }

    // Step 3: authorization — has capability?
    if !requiredCap(p) {
        return fmt.Errorf("participant %q lacks required capability", declaredSource)
    }

    return nil
}

// Usage in directive handler:
err := validateIPCSource(ctx, s.participants, input.Source,
    func(p *participant.Participant) bool { return p.CanIssueDirectives })
```

### 3.7 MCP admin tools (participant management)

Management through MCP conversation (the natural admin interface):

| Tool | Purpose | Auth gate |
|------|---------|-----------|
| `register_participant` | Create new participant with capabilities | `human` platform only |
| `update_participant` | Modify capabilities, description | `human` platform only |
| `list_participants` | View all participants + capabilities | Any authenticated caller |
| `deactivate_participant` | Set all capability flags to false | `human` platform only |

Write tools restricted to `human` platform — Koopa operating directly, not through an AI agent. This prevents an AI session from modifying its own capabilities.

Example flow:
```
Koopa: "Register new-project as a claude-code participant, task assignable and can receive directives"

Claude calls: register_participant(
    name: "new-project",
    platform: "claude-code",
    description: "New side project",
    task_assignable: true,
    can_receive_directives: true
)

Response: {
    "status": "created",
    "participant": { "name": "new-project", "platform": "claude-code", ... },
    "setup_instructions": {
        "stdio": "claude mcp add koopa0-dev --command koopa-mcp --args '--platform=claude-code'",
        "http": "Use existing claude-code platform token, or register a new OAuth client"
    }
}
```

### 3.8 How new platforms/participants join the system

#### Adding a new participant to an existing platform

1. Koopa tells Claude: "Register X on platform Y with capabilities Z"
2. MCP tool writes to `participant` table
3. The new Claude project uses the same platform token/config as other projects on that platform
4. Done — no new credentials needed

Example: Adding a new Claude Code project `side-project` to the `claude-code` platform:
- DB: `INSERT INTO participant (name, platform, task_assignable) VALUES ('side-project', 'claude-code', true)`
- Config: The new project uses the same `--platform=claude-code` flag or same HTTP token as `koopa0.dev`
- The participant store resolves `side-project` → `claude-code` → capabilities

#### Adding a new platform entirely

Rare — a new platform means a new execution environment. Steps:

1. DB: `INSERT INTO platform (name, description) VALUES ('new-platform', '...')`
2. DB: `INSERT INTO participant (name, platform, ...) VALUES ('first-participant', 'new-platform', ...)`
3. Auth: Generate platform token (static or OAuth client registration with platform binding)
4. Client config: Use the new token

This is an admin operation. Could be an MCP tool (`register_platform`) but rare enough that manual SQL is acceptable.

---

## 4. Anthropic Infrastructure — What We Can and Can't Know

### How remote MCP connections work

When Claude Desktop or claude.ai adds your MCP server as a Connector:

```
Claude client → Anthropic cloud infra → HTTPS → mcp.koopa0.dev
```

The HTTP request your server receives comes from **Anthropic's IP ranges**, not from the user's machine. You cannot use source IP to identify the client.

### What you CAN know from the request

1. **Bearer token** — issued during OAuth flow. If platform-bound, identifies the platform.
2. **MCP session ID** (`Mcp-Session-Id` header) — identifies a specific connection session. Same client reconnecting gets the same session. Different clients get different sessions.
3. **OAuth client_id** — if the client did Dynamic Client Registration, you know which client_id was used. If that client_id is bound to a platform, you know the platform.

### What you CANNOT know

1. **Which specific Claude conversation** triggered the tool call — Anthropic doesn't expose this
2. **Whether it's Claude Desktop vs claude.ai** — unless they registered with different OAuth clients
3. **The user's IP** — requests come from Anthropic infra

### Implication for platform identification

The token is your only reliable identity signal. This is why platform binding on the token is essential — there's no other way to distinguish callers once the request arrives at your server.

---

## 5. Schema Impact

**No schema changes needed.** The existing `platform` and `participant` tables already model the identity hierarchy correctly. All capability flags are in place. The `ON DELETE RESTRICT` on participant FKs prevents accidental deletion.

The only new artifact is Go code:
- `internal/participant/` store (reads existing tables)
- `mcpauth` changes (platform binding on tokens)
- Validation middleware/functions
- MCP admin tools

---

## 6. Implementation Phases

### Phase 0: Participant store (foundation)

**Scope**: `internal/participant/` — store that reads `platform` + `participant` tables.
**Depends on**: Schema applied (tables exist).
**Enables**: Everything else.

### Phase 1: stdio platform identity

**Scope**: `--platform` flag on `cmd/mcp/main.go`, platform stored in context for all tool calls.
**Depends on**: Phase 0.
**Risk**: None — local process, implicit trust.

Immediate value: Every tool call from stdio now has a verified platform context. `validateIPCSource` can enforce participant-platform binding.

### Phase 2: HTTP per-platform static tokens

**Scope**: Replace single `MCP_TOKEN` with per-platform tokens. `BearerAuth` resolves token → platform.
**Depends on**: Phase 0.
**Risk**: Low — config change, no OAuth flow modification.

`mcpauth.Provider` changes:
- `staticToken string` → `staticTokens map[string]string` (token → platform)
- `ValidToken(tok) bool` → `ValidateToken(tok) (platform string, ok bool)`

Env var: `MCP_PLATFORM_TOKENS=claude-cowork:aaa,claude-code:bbb,claude-web:ccc`

### Phase 3: OAuth platform binding

**Scope**: Dynamic Client Registration with `platform` field. Token issuance carries platform. Platform selection page as fallback.
**Depends on**: Phase 2 (static tokens provide the validation chain, OAuth adds ergonomics).
**Risk**: Medium — OAuth flow changes, needs testing with Claude Desktop Connector and claude.ai.

Changes to `mcpauth.Provider`:
- `clients map[string]string` → `map[string]clientInfo` (adds platform)
- `tokens map[string]time.Time` → `map[string]tokenInfo` (adds platform)
- `Register` handler accepts `platform` field
- `GoogleCallback` → if client has no platform → platform selection page → then issue code
- `issueToken` inherits platform from client/auth-session

### Phase 4: MCP admin tools

**Scope**: `register_participant`, `update_participant`, `list_participants`, `deactivate_participant` MCP tools.
**Depends on**: Phase 0.
**Risk**: Low — read/write to existing tables.

Can be done in parallel with Phase 1-3.

### Phase 5: IPC tool hardening

**Scope**: Every IPC tool handler calls `validateIPCSource`. Non-IPC tools that write data get platform-aware audit logging.
**Depends on**: Phase 1 (stdio) or Phase 2 (HTTP) — need at least one transport providing platform identity.

Affected tools:
- `save_session_note` (journal, insights) — validate `source` param
- `create_directive` (when implemented as separate tool) — validate `source` + `target`
- `create_report` (when implemented) — validate `source`
- `create_task` — validate `created_by` param
- `complete_task` — audit which platform completed it

---

## 7. Persistence Consideration

Current `mcpauth.Provider` stores all state in memory (`map[string]...`). Server restart = all OAuth clients, tokens, and refresh tokens are lost. Clients must re-register and re-authenticate.

This is acceptable for a personal system **today** (restarts are rare, re-auth is fast). But with platform binding, losing the client→platform mapping means platform identity is lost until re-registration.

Options:
1. **Keep in-memory** — acceptable if restarts are rare and clients re-register automatically
2. **Persist to DB** — add `oauth_clients` table for registered clients with platform binding. Tokens stay in-memory (short TTL).
3. **Persist to file** — JSON file alongside config. Simpler than DB.

Recommendation: Start with in-memory. Move to DB persistence (`oauth_clients` table) when stability is needed. This is a Phase 3+ concern.

---

## 8. Open Questions

### Q1: Should `MCP_TOKEN` (static) coexist with OAuth long-term?

Currently, Claude Code CLI with `--header "Authorization: Bearer <MCP_TOKEN>"` uses the static token. OAuth is for Claude Desktop/claude.ai Connectors. Both are valid entry points.

**Recommendation**: Keep both. Static tokens for machine-to-machine (Claude Code remote), OAuth for browser-mediated flows (Connectors). Both resolve to a platform identity.

### Q2: Should the participant store cache?

At personal scale (8 participants), every `validateIPCSource` call hits the DB for a single-row lookup by PK. This is ~0.1ms on localhost. No cache needed.

If participant count grows or tool call frequency is very high, add an in-memory cache with short TTL (1 min). The `participant` table is rarely written.

### Q3: What happens when a legitimate caller sends wrong source?

Example: Claude Code session accidentally sends `source="hq"` instead of `source="koopa0.dev"`.

Step 2 catches this: "participant hq belongs to platform claude-cowork, not claude-code."

The MCP tool should return a clear error message so the coaching prompt can self-correct:
```json
{
    "error": "source 'hq' is not a participant on platform 'claude-code'. Available participants for this platform: koopa0.dev, go-spec"
}
```

### Q4: Should the platform selection page be a full HTML page or a redirect?

For claude.ai and Claude Desktop Connectors, the OAuth flow opens a browser window. After Google login, the platform selection could be:
- **HTML form** served by the MCP server (simplest, but requires the server to serve HTML)
- **Redirect to a separate admin page** on `koopa0.dev` frontend

**Recommendation**: Simple HTML page served directly from `mcpauth.go`. It's one page with 3-4 radio buttons. No frontend framework needed.

---

## 9. Decision Checklist

Before implementing, confirm these decisions:

- [ ] Phase 1 (stdio `--platform` flag): proceed?
- [ ] Phase 2 (per-platform static tokens via `MCP_PLATFORM_TOKENS` env var): proceed?
- [ ] Phase 3 (OAuth platform binding): proceed or defer?
- [ ] Phase 4 (MCP admin tools for participant management): proceed?
- [ ] `human` platform as the admin gate for write tools: agree?
- [ ] In-memory token storage acceptable for now?
- [ ] Platform selection page as simple HTML form: agree?

---

## 10. Cross-References

| Document | Relevance |
|----------|-----------|
| `migrations/001_initial.up.sql` lines 62-108 | `platform` + `participant` table definitions + seed data |
| `internal/mcpauth/mcpauth.go` | Current OAuth2 implementation (full file) |
| `cmd/mcp/main.go` lines 103-111 | Dual transport switch |
| `cmd/mcp/main.go` lines 243-312 | HTTP server setup + OAuth endpoint wiring |
| `cmd/mcp/config.go` | Environment variable configuration |
| `internal/mcp/write.go:855-905` | `saveSessionNote` — current IPC write path (no source validation) |
| `internal/mcp/search.go:1009-1026` | Source whitelist for reads (not writes) |
| `docs/PARTICIPANT-CAPABILITIES-AND-SCHEDULES.md` | Capability flag semantics + schedule design |
| `docs/LEARNING-ANALYTICS-SCHEMA-DESIGN.md` §4.3 | Learning sessions without participant column |
| MCP spec 2025-11-25 | OAuth 2.1 + PKCE + Resource Indicators + Protected Resource Metadata |
