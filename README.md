# Koopa

[![CI](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/koopa0/koopa-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/koopa0/koopa-cli)](https://goreportcard.com/report/github.com/koopa0/koopa-cli)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Koopa is a local-first AI workspace platform built with Go.

It unifies terminal efficiency with rich web interactions through a hybrid architecture: a keyboard-centric TUI for speed, and a server-driven Web UI for visualization. Powered by Firebase Genkit and PostgreSQL, Koopa enables local knowledge management, autonomous agents, and tool integration via the Model Context Protocol (MCP).

## Core Philosophy

- **Local Sovereignty**: User data, sessions, and vector embeddings reside in a local PostgreSQL database.
- **Hybrid Interface**: Seamless context switching between CLI efficiency and Web UI richness.
- **Hypermedia-Driven**: Utilizes a modern Go stack (Templ + HTMX) to deliver high performance with low complexity.

## Features

- **Generative Web UI**: A server-driven interface supporting streaming responses, rich component rendering, and artifact management without SPA complexity.
- **Terminal UI**: A low-latency Bubble Tea application for rapid interaction.
- **Local RAG**: Automatic document indexing using `pgvector` for context-aware conversations.
- **MCP Integration**: Implements the Model Context Protocol to serve as a backend for compatible clients like Claude Desktop.
- **Session Persistence**: Robust conversation history management across all interfaces.

## Technology Stack

- **Language**: Go 1.25+
- **AI Framework**: Google Firebase Genkit
- **Database**: PostgreSQL + pgvector
- **Web**: Templ, HTMX, Tailwind CSS
- **TUI**: Bubble Tea

## Quick Start

### Prerequisites

- Go 1.25 or higher
- Docker (for PostgreSQL)
- Node.js 20+ (asset compilation only)
- Gemini API Key

### Installation

1.  **Clone and setup**

    ```bash
    git clone https://github.com/koopa0/koopa-cli.git
    cd koopa-cli
    go install github.com/go-task/task/v3/cmd/task@latest
    task install
    ```

2.  **Start infrastructure**

    ```bash
    docker-compose up -d
    ```

3.  **Build**

    ```bash
    task build
    ```

4.  **Configure**
    Create `~/.koopa/config.yaml`:

    ```yaml
    postgres_host: "localhost"
    postgres_port: 5432
    postgres_user: "koopa"
    postgres_db_name: "koopa"
    postgres_ssl_mode: "disable"
    ```

5.  **Run**
    ```bash
    export GEMINI_API_KEY="your-key"
    ./koopa
    ```

## Usage

Koopa operates in three modes.

**Terminal Mode**
The default interactive interface.

```bash
./koopa
```

**Web Server Mode**
Starts the HTTP server for the web interface.

```bash
export HMAC_SECRET=$(openssl rand -base64 32)
./koopa serve
```

Access the UI at `http://localhost:8080/genui`.

**MCP Server Mode**
Exposes tools and knowledge base to external MCP clients.

```bash
./koopa mcp
```

## Configuration

Koopa uses a config-first approach. Non-sensitive settings reside in `config.yaml`, while secrets must be passed via environment variables.

**Environment Variables**

- `GEMINI_API_KEY`: Required. Google AI API key.
- `HMAC_SECRET`: Required for `serve` mode. Min 32 chars.
- `POSTGRES_PASSWORD`: Required if not using default credentials.

**Configuration File**
Default settings in `~/.koopa/config.yaml`:

```yaml
model_name: "gemini-2.5-flash"
temperature: 0.7
max_tokens: 4096
rag_top_k: 5
embedder_model: "text-embedding-004"
```

## Development

Use `Taskfile` for standard workflows.

```bash
task generate css   # Build assets
task test           # Run unit tests
task test:race      # Run tests with race detector
task dev            # Start dev server with hot-reload
```

## Contributing

1.  Fork the repository.
2.  Create a feature branch.
3.  Ensure `task test:race` passes.
4.  Submit a Pull Request.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
