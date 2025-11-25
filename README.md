# Koopa CLI

[![CI](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/koopa0/koopa-cli)](https://goreportcard.com/report/github.com/koopa0/koopa-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal-based AI assistant with local knowledge management and MCP integration. Built with [Firebase Genkit](https://github.com/firebase/genkit).

**Version**: 0.1.0 (Alpha)

## What is Koopa?

Koopa is a personal AI assistant designed for developers who want:

- **Local Knowledge**: Index your documents, code, and notes for context-aware conversations
- **Privacy Control**: All data stays on your machine
- **MCP Integration**: Connect with Gemini CLI, Cursor, Claude Code via Model Context Protocol
- **Extensible Tools**: File operations, system commands, HTTP requests, knowledge search
- **Session Management**: Persistent conversations organized by topic

Unlike generic AI assistants, Koopa learns from your local documents and integrates seamlessly into your development workflow.

## Quick Start

**Prerequisites**: Go 1.25+, Docker, PostgreSQL, [Gemini API key](https://ai.google.dev/)

```bash
# Clone and build
git clone https://github.com/koopa0/koopa-cli.git
cd koopa-cli
go build -o koopa

# Start database
docker-compose up -d

# Set API key and run
export GEMINI_API_KEY=your-api-key
./koopa
```

## Features

### Local Knowledge Base
Index your documents for semantic search:
```bash
> /rag add ~/Documents/notes/
> /rag add ~/projects/myapp/docs/
> What did I write about microservices?
```

### MCP Server
Run Koopa as an MCP server to integrate with other tools:
```bash
$ ./koopa mcp
```

Configure in `~/.gemini/settings.json`:
```json
{
  "mcpServers": {
    "koopa": {
      "command": "koopa",
      "args": ["mcp"]
    }
  }
}
```

Use from Gemini CLI:
```bash
$ gemini
> @koopa search my notes for "deployment strategies"
```

### Session Management
Organize conversations by topic:
```bash
> /session new "Project Planning"
> /session list
> /session switch <session-id>
```

### Built-in Tools
- **File Operations**: Read, write, list, delete files with path validation
- **System Commands**: Execute shell commands with security whitelist
- **HTTP Requests**: Make web requests with SSRF protection
- **Knowledge Search**: Semantic search over indexed documents

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                       │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                    Chat Agent (Genkit)                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   Tools     │  │   Sessions   │  │   Knowledge    │  │
│  │  Registry   │  │   (Postgres) │  │   (pgvector)   │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
        ┌──────────────┐        ┌──────────────┐
        │  MCP Server  │        │   RAG        │
        │  (Stdio)     │        │  Retriever   │
        └──────────────┘        └──────────────┘
```

### Core Components

- **Agent**: Stateless agent with tool calling and RAG
- **Tools**: Modular toolsets (file, system, network, knowledge)
- **MCP**: Model Context Protocol server for external integration
- **Knowledge**: Vector-based semantic search with pgvector
- **Session**: PostgreSQL-backed conversation persistence
- **RAG**: Document indexing and retrieval
- **Security**: Path validation, command whitelist, SSRF protection

## Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/session new <title>` | Create new session |
| `/session list` | List all sessions |
| `/session switch <id>` | Switch to session |
| `/rag add <path>` | Index documents |
| `/rag list` | List indexed documents |
| `/rag status` | Show RAG statistics |
| `/exit` | Exit Koopa |

## Configuration

Create `~/.koopa/config.yaml`:

```yaml
# Model settings
model_name: "gemini-2.5-flash"
temperature: 0.7
max_tokens: 2048

# RAG settings
rag_top_k: 3
embedder_model: "text-embedding-004"

# Session settings
max_history_messages: 50
```

## Development

```bash
# Run tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run linter
golangci-lint run

# Build
go build -o koopa
```

## Roadmap

### Current (v0.1.0)
- CLI interface
- Local knowledge base (RAG)
- MCP server integration
- Session management
- Built-in security

### Planned (v0.2.0)
- HTTP API server
- Genkit flows for programmatic access
- Enhanced tool system
- Multi-agent support

### Future
- Deep research engine (inspired by Perplexity/NotebookLM)
- Knowledge graph
- Web UI
- Cloud deployment support

See [KOOPA_EVOLUTION_PROPOSAL.md](KOOPA_EVOLUTION_PROPOSAL.md) for detailed roadmap.

## Integration

### Gemini CLI
```bash
# In ~/.gemini/settings.json
{
  "mcpServers": {
    "koopa": {
      "command": "koopa",
      "args": ["mcp"]
    }
  }
}
```

### Cursor IDE
```json
// In .cursor/mcp.json
{
  "mcpServers": {
    "koopa": {
      "command": "koopa",
      "args": ["mcp"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

### Claude Code
Add Koopa as an MCP server in Claude Code settings.

## Documentation

- [Architecture](docs/architecture/) - System design and patterns
- [Testing Strategy](TESTING_STRATEGY_PROPOSAL.md) - Test plan and coverage
- [Evolution Roadmap](KOOPA_EVOLUTION_PROPOSAL.md) - Future development plans
- [API Reference](https://pkg.go.dev/github.com/koopa0/koopa-cli) - Package documentation

## Contributing

Contributions welcome! Please:

1. Read the [contributing guidelines](CONTRIBUTING.md)
2. Fork and create a feature branch
3. Write tests for new functionality
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built with [Firebase Genkit](https://github.com/firebase/genkit) • Powered by Gemini • Open Source**
