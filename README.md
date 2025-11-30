# Koopa

[![CI](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/koopa0/koopa-cli)](https://goreportcard.com/report/github.com/koopa0/koopa-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal-based AI assistant with local knowledge management, built with [Firebase Genkit](https://github.com/firebase/genkit).

## Features

- **Local Knowledge Base** - Index your documents for context-aware conversations
- **Session Persistence** - Conversations are saved and can be resumed
- **Built-in Tools** - File operations, system commands, and HTTP requests
- **MCP Integration** - Works with Claude Desktop, Cursor, and Gemini CLI
- **HTTP API** - Programmatic access for automation

## Installation

**Prerequisites:** Go 1.25+, Node.js 20+, Docker, [Gemini API key](https://ai.google.dev/)

```bash
git clone https://github.com/koopa0/koopa-cli.git
cd koopa-cli

# Install Task (build tool)
go install github.com/go-task/task/v3/cmd/task@latest

# Install dependencies and build
task install   # Install frontend deps and templ
task build     # Build binary with all assets

# Start database
docker-compose up -d

# Run
export GEMINI_API_KEY=your-api-key
./koopa
```

## Usage

```
$ ./koopa
Koopa - Your terminal AI personal assistant

> Hello!
Koopa> Hi! How can I help you today?

> /help
```

**Other modes:**

```bash
./koopa serve   # HTTP API server (requires HMAC_SECRET)
./koopa mcp     # MCP server for external tools
```

## Configuration

### Required Environment Variables

| Variable | Required For | Description | Configuration |
|----------|--------------|-------------|---------------|
| `GEMINI_API_KEY` | All modes | Google AI API key | Environment variable only |
| `hmac_secret` | `serve` mode | CSRF token secret (min 32 chars) | Set in `~/.koopa/config.yaml` |
| `postgres_*` | All modes | Database connection | Set in `~/.koopa/config.yaml` |

**Example config.yaml:**
```yaml
# ~/.koopa/config.yaml
postgres_host: "localhost"
postgres_port: 5432
postgres_user: "koopa"
postgres_password: ""  # or set KOOPA_POSTGRES_PASSWORD env var
postgres_db_name: "koopa"
postgres_ssl_mode: "disable"

hmac_secret: "your-32-char-secret"  # Generate with: openssl rand -base64 32
```

**Example usage:**
```bash
export GEMINI_API_KEY=your-api-key
./koopa serve
```

See [config.example.yaml](config.example.yaml) for all configuration options.

## Development

### Local Development Workflow

```bash
# Build frontend assets (required before tests)
task css

# Generate templ files
task generate

# Run tests
task test

# Run tests with race detector
task test:race

# Development server (auto-reload)
task dev
```

### Viewing the Web UI

The web interface is available when running in serve mode:

```bash
# Set API key (required)
export GEMINI_API_KEY=your-api-key

# Configure database in ~/.koopa/config.yaml:
#   postgres_host: localhost
#   postgres_port: 5432
#   postgres_user: koopa
#   postgres_password: ""  # or set KOOPA_POSTGRES_PASSWORD env var
#   postgres_db_name: koopa
#   postgres_ssl_mode: disable
#
#   hmac_secret: "..."  # Generate with: openssl rand -base64 32

./koopa serve
# Visit http://localhost:3400/genui
```

## Contributing

1. Fork and create a feature branch
2. Build assets: `task generate css`
3. Ensure tests pass: `task test:race`
4. Submit a pull request

## License

[LICENSE](LICENSE)
