# Koopa Project Guidelines

A terminal-based AI assistant with local knowledge management, built with Firebase Genkit.

## Quick Reference

```bash
# Build
go build -o koopa ./...

# Test (with race detector)
go test -race ./...

# Lint
golangci-lint run

# Run
./koopa           # Interactive CLI
./koopa serve     # HTTP API server
./koopa mcp       # MCP server
```

## Project Structure

```
koopa/
├── cmd/              # CLI commands (cobra)
├── internal/
│   ├── agent/        # Agent abstraction layer
│   │   └── chat/     # Chat agent with Genkit Flow
│   ├── api/          # JSON REST API server, SSE streaming
│   ├── app/          # Application lifecycle (DI)
│   ├── config/       # Configuration loading
│   ├── knowledge/    # Knowledge store (pgvector)
│   ├── mcp/          # MCP server implementation
│   ├── rag/          # RAG retriever/indexer
│   ├── security/     # Validators (path, command, env, HTTP)
│   ├── session/      # Session persistence (PostgreSQL)
│   ├── tools/        # Toolsets (File, System, Network, Knowledge)
│   └── ui/           # Console I/O
└── db/               # SQL migrations
```

## Development Workflow

### CRITICAL: Git Operations Policy

**Claude Code is STRICTLY FORBIDDEN from executing ANY git commands.**

This includes but is not limited to:

- ❌ `git add`
- ❌ `git commit`
- ❌ `git push`
- ❌ `git pull`
- ❌ `git checkout`
- ❌ `git branch`
- ❌ `git merge`
- ❌ `git rebase`
- ❌ `git stash`
- ❌ `git reset`
- ❌ `git rm`
- ❌ ANY other git command

**What Claude Code SHOULD do instead**:

- ✅ Make code changes using Write/Edit tools
- ✅ Run tests to verify changes
- ✅ Run linters to verify code quality
- ✅ **INFORM the user** what git commands they should run manually

**Example correct behavior**:

```
Claude: I've completed the implementation. Here are the git commands YOU should run:

git add internal/testutil/embedder.go
git commit -m "refactor: remove duplicate embedder.go"
```

**Rationale**:

- User maintains full control over version control
- Prevents accidental commits with incorrect messages
- Avoids potential conflicts or destructive operations
- User can review changes before committing

### MANDATORY: Proposal Before Implementation

**CRITICAL RULE**: You MUST get proposal approval BEFORE any implementation.

Before implementing ANY feature or change:

1. **Propose** the approach first (create proposal document in `docs/proposals/`)
2. **Wait for master review** - The reviewer subagents MUST validate your proposal
3. **Get explicit approval** - Wait for user's "yes" or "ok" to proceed
4. **Only implement after approval** - NEVER start coding without approved proposal

**STRICTLY FORBIDDEN**:

- ❌ Implementing based on verbal discussion without written proposal
- ❌ Starting implementation before masters review the proposal
- ❌ Making changes without explicit user approval
- ❌ "Fixing things" proactively without proposal
- ❌ Assuming approval - ALWAYS wait for explicit "yes"

**Correct workflow example**:

```
User: "Add feature X"
Claude: [Creates docs/proposals/NNN-feature-x.md]
Claude: [Invokes masters to review]
Masters: [All APPROVED]
Claude: "Proposal approved. Should I implement?"
User: "yes"  ← REQUIRED
Claude: [Starts implementation]
```

This applies to:

- New features
- Bug fixes (beyond trivial typos)
- Refactoring
- Architecture changes
- Adding dependencies
- Any code modification

### MANDATORY: Master Collaboration for Decision-Making

**CRITICAL RULE**: Claude Code MUST NOT make architectural or design decisions independently.

**When facing design questions**, you MUST:

1. **Identify the domain** - Which master(s) should be consulted?
2. **Invoke the master(s)** - Use Task tool to get expert review
3. **Present options** - Summarize master recommendations to user
4. **Wait for user decision** - Do NOT implement based on your own judgment

**Examples requiring master collaboration**:

#### UI/Frontend Decisions

```
User: "We need interactive components like modals and dropdowns"
Claude: ❌ "Let me add Alpine.js" (unilateral decision)
Claude: ✅ [Invokes ui-master and htmx-master] → Presents options → Waits for user decision
```

#### Database Schema Changes

```
User: "Add caching to reduce database load"
Claude: ❌ "I'll add Redis" (unilateral decision)
Claude: ✅ [Invokes psql-master and architecture-master] → Presents options → Waits for user decision
```

#### Dependency Addition

```
User: "We need better error handling"
Claude: ❌ "I'll install pkg/errors" (unilateral decision)
Claude: ✅ [Invokes golang-master and architecture-master] → Presents options → Waits for user decision
```

**Master consultation is MANDATORY for**:

- UI architecture decisions (ui-master)
- Database design (psql-master)
- AI/LLM integration (genkit-master, ai-agent-master)
- System design (architecture-master)
- Security concerns (security domain masters)
- Testing strategy (qa-master)
- Go language patterns (golang-master, rob-pike)

**Workflow**:

```
1. User asks question with design implications
2. Claude identifies relevant domain (UI, DB, Architecture, etc.)
3. Claude invokes corresponding master(s) using Task tool
4. Master(s) provide expert analysis with pros/cons
5. Claude summarizes recommendations WITHOUT adding own opinion
6. User makes final decision
7. Claude implements user's chosen approach
```

**STRICTLY FORBIDDEN**:

- ❌ Making architectural decisions based on Claude Code's "judgment"
- ❌ Choosing technologies without master review
- ❌ Implementing solutions before presenting master recommendations to user
- ❌ Filtering or biasing master feedback based on personal preference
- ❌ Saying "I recommend X" without master consultation

**Correct behavior**:

```
User: "Should we use @tailwindplus/elements?"

Claude (WRONG):
"I don't recommend it because of CSP issues." ← Unilateral decision

Claude (CORRECT):
"Let me consult ui-master and htmx-master about this."
[Invokes masters]
[Presents FULL master analysis]
"ui-master suggests native HTML, htmx-master says Elements is complementary.
Which approach do you prefer?"
```

**Rationale**:

- User maintains architectural control
- Expert domain knowledge drives decisions
- Multiple perspectives reduce bias
- Clear separation: masters analyze, user decides, Claude implements

### MANDATORY: Review After Implementation

After implementing ANY code:

1. **Run tests** with race detector: `go test -race ./...`
2. **Invoke reviewer subagents** to validate the implementation
3. **Address all feedback** before considering complete

## Code Standards

### Go Style (Strictly Enforced)

- Follow Effective Go, Google Style Guide, and Uber Style Guide
- Standard library preferred over external dependencies
- Error handling: always wrap with context using `fmt.Errorf("context: %w", err)`
- Naming: short for small scope, descriptive for exported
- Concurrency: protect shared state, avoid goroutine leaks

### Testing Philosophy

- Test for real scenarios, not coverage metrics
- Unit tests for business logic
- Integration tests for database/external services
- Fuzz tests for security-sensitive input parsing
- Benchmark tests for performance-critical paths
- Race tests: always run with `-race` flag

### Security Requirements

- SSRF protection in network tools
- Path traversal prevention in file tools
- Command injection prevention in system tools
- SQL injection prevention via parameterized queries
- Sensitive data protection (API keys, secrets)

## Key Patterns

### Genkit Integration

This project uses Firebase Genkit for AI agent orchestration:

- `genkit.DefineStreamingFlow()` for SSE streaming
- `genkit.Handler()` for HTTP endpoints
- Singleton pattern for Flow registration (sync.Once)

### Dependency Injection

Use struct-based dependency injection:

```go
chatAgent, err := chat.New(chat.Config{
    Genkit:       g,
    SessionStore: store,
    Tools:        allTools,
    Logger:       logger,
})
```

## Available Reviewer Subagents

The following expert reviewers are available and SHOULD BE USED proactively:

### Core Reviewers (Always Available)

- **golang-master**: Go best practices, naming, stdlib usage
- **rob-pike** (opus): Go purist - strictest review, simplicity obsession, questions everything
- **psql-master**: Database design, queries, migrations
- **genkit-master**: Genkit patterns, Flow design, AI integration
- **qa-master**: Testing strategy, edge cases, coverage
- **architecture-master**: System design, reliability, scalability, duplication detection
- **ai-agent-master**: AI/ML best practices, industry patterns

### Frontend Reviewers (When Angular UI Work)

- **ui-master**: Angular components, Material Design, responsive, accessibility

## Available Commands

| Command         | Purpose                                                   |
| --------------- | --------------------------------------------------------- |
| `/propose X`    | Propose a feature for master review before implementation |
| `/implement X`  | Start implementation with workflow checks                 |
| `/review X`     | Full multi-master review panel                            |
| `/codereview X` | Deep code review by Rob Pike + critical masters           |
| `/validate X`   | Post-implementation validation                            |
| `/quickcheck`   | Fast build + test + lint check                            |
| `/status`       | Project status report                                     |

## Import References

@./docs/ARCHITECTURE.md
@./GENKIT.md

<genkit_prompts hash="7fb2e1d5">

<!-- Genkit Context - Auto-generated, do not edit -->

Genkit Framework Instructions:

- @./GENKIT.md

</genkit_prompts>
