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

**Prerequisites:** Go 1.24+, Docker, [Gemini API key](https://ai.google.dev/)

```bash
git clone https://github.com/koopa0/koopa-cli.git
cd koopa-cli
go build -o koopa

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
./koopa serve   # HTTP API server
./koopa mcp     # MCP server for external tools
```

## Contributing

1. Fork and create a feature branch
2. Ensure tests pass: `go test ./...`
3. Submit a pull request

## License

[LICENSE](LICENSE)
