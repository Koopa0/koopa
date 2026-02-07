# Koopa

[![CI](https://github.com/koopa0/koopa/actions/workflows/ci.yml/badge.svg)](https://github.com/koopa0/koopa/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/koopa0/koopa)](https://goreportcard.com/report/github.com/koopa0/koopa)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal AI assistant with local knowledge management. Supports Gemini, Ollama, and OpenAI.

## Features

- **Multi-provider** — Switch between Gemini, Ollama (local), and OpenAI with an environment variable
- **Interactive TUI** — Chat in your terminal with streaming responses
- **HTTP API** — JSON REST API with SSE streaming for building frontends
- **MCP Server** — Use Koopa's tools from Claude Desktop or Cursor
- **RAG** — Semantic search over your conversations and documents (pgvector)
- **Built-in tools** — File I/O, shell commands, web search, web scraping
- **MCP client** — Plug in external MCP servers for additional tools
- **Sessions** — Persistent conversation history in PostgreSQL

## Quick Start

```bash
# 1. Start PostgreSQL with pgvector
docker compose up -d postgres

# 2. Configure
cp .env.example .env
# Edit .env — set GEMINI_API_KEY and DATABASE_URL
source .env

# 3. Build and run
go build -o koopa .
./koopa cli
```

## Usage

```
koopa cli          Interactive chat
koopa serve [addr] HTTP API server (default: 127.0.0.1:3400)
koopa mcp          MCP server for IDE integration
koopa --version    Version info
```

### CLI Commands

| Command    | Description                |
|------------|----------------------------|
| `/help`    | Show available commands    |
| `/clear`   | Clear conversation history |
| `/exit`    | Exit Koopa                 |
| `Ctrl+D`   | Exit                       |

### HTTP API

```bash
export HMAC_SECRET=$(openssl rand -base64 32)
./koopa serve
```

| Endpoint                        | Method | Description              |
|---------------------------------|--------|--------------------------|
| `/api/chat`                     | POST   | Send message (SSE stream)|
| `/api/sessions`                 | GET    | List sessions            |
| `/api/sessions`                 | POST   | Create session           |
| `/api/sessions/{id}`            | GET    | Get session              |
| `/api/sessions/{id}`            | DELETE | Delete session           |
| `/api/sessions/{id}/messages`   | GET    | Get session messages     |
| `/health`                       | GET    | Health check             |

### MCP Server

Add to Claude Desktop or Cursor config:

```json
{
  "mcpServers": {
    "koopa": {
      "command": "/path/to/koopa",
      "args": ["mcp"],
      "env": {
        "GEMINI_API_KEY": "your-key",
        "DATABASE_URL": "postgres://koopa:password@localhost:5432/koopa?sslmode=disable"
      }
    }
  }
}
```

Tools: `read_file`, `write_file`, `list_directory`, `execute_command`, `get_env`, `web_search`, `web_fetch`, `search_history`, `search_documents`, `search_system_knowledge`.

## Providers

### Gemini (default)

```bash
export GEMINI_API_KEY=your-key
./koopa cli
```

### Ollama

```bash
ollama pull llama3.3
export KOOPA_PROVIDER=ollama
export KOOPA_MODEL_NAME=llama3.3
./koopa cli
```

### OpenAI

```bash
export OPENAI_API_KEY=your-key
export KOOPA_PROVIDER=openai
export KOOPA_MODEL_NAME=gpt-4o
./koopa cli
```

## Configuration

Priority: Environment variables > `~/.koopa/config.yaml` > defaults.

| Variable             | Required | Default                  | Description                         |
|----------------------|----------|--------------------------|-------------------------------------|
| `GEMINI_API_KEY`     | Gemini   | -                        | Google AI API key                   |
| `OPENAI_API_KEY`     | OpenAI   | -                        | OpenAI API key                      |
| `DATABASE_URL`       | Yes      | -                        | PostgreSQL connection URL           |
| `HMAC_SECRET`        | Serve    | -                        | CSRF secret (min 32 chars)          |
| `KOOPA_PROVIDER`     | No       | `gemini`                 | AI provider: gemini, ollama, openai |
| `KOOPA_MODEL_NAME`   | No       | `gemini-2.5-flash`       | Model identifier                    |
| `KOOPA_OLLAMA_HOST`  | No       | `http://localhost:11434` | Ollama server address               |
| `DEBUG`              | No       | -                        | Enable debug logging                |

For MCP server connections and web search configuration, see [config.example.yaml](config.example.yaml).

## Docker Compose

```bash
docker compose up -d postgres           # PostgreSQL only
docker compose up -d                     # + SearXNG web search
```

| Service    | Port | Description                      |
|------------|------|----------------------------------|
| PostgreSQL | 5432 | Database with pgvector           |
| SearXNG    | 8888 | Privacy-respecting web search    |

## Prerequisites

- Go 1.25+
- Docker (for PostgreSQL)

## License

MIT
