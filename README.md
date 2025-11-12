# Koopa CLI

![Koopa Assistant](docs/assets/Koopa-CLI.jpg)

**A terminal-based AI assistant with knowledge base capabilities, built on [Genkit](https://github.com/firebase/genkit).**

Koopa brings AI conversations directly to your command line with the ability to index and search your local documents for context-aware responses.

## Features

| Feature                  | Description                                                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Interactive Chat**     | Start conversations instantly with `./koopa` - no configuration needed beyond your API key                                          |
| **Knowledge Base (RAG)** | Index your documents, code, and notes. Koopa automatically retrieves relevant content to answer your questions                      |
| **Local & Private**      | Your documents stay on your machine. Vector embeddings stored in your local PostgreSQL database                                     |
| **Extensible Tools**     | Built-in file operations, system commands, and HTTP requests. Add custom tools via [MCP protocol](https://modelcontextprotocol.io/) |

## Quick Start

**Prerequisites:** Go 1.23+, Docker & Docker Compose, and a [Gemini API key](https://ai.google.dev/)

```bash
# Clone and setup
git clone https://github.com/koopa0/koopa-cli.git
cd koopa-cli

# Start database (auto-runs migrations)
docker-compose up -d

# Build and run
go build -o koopa
export GEMINI_API_KEY=your-api-key
./koopa
```

## Usage

### Chat Mode

```bash
$ ./koopa

╔══════════════════════════════════════════════════════════╗
║  Koopa v1.0                                              ║
║  AI Personal Assistant powered by Gemini                 ║
║                                                          ║
║  Type /help for commands, Ctrl+D to exit                 ║
╚══════════════════════════════════════════════════════════╝

You> What's the weather like today?
Koopa> I can help you check the weather...
```

### Knowledge Base

```bash
# Index your documents
You> /rag add ~/Documents/notes/

# Ask questions about them
You> What are my meeting notes from last week?
Koopa> [Retrieves and references your indexed documents]

# Manage your knowledge base
You> /rag list          # View all indexed documents
You> /rag status        # Check system status
```

### Available Commands

- `/help` - Show available commands
- `/rag add <path>` - Index files or directories
- `/rag list` - List indexed documents
- `/rag status` - Show knowledge base status
- `/clear` - Clear conversation history
- `/exit` - Exit Koopa

## Configuration

Koopa works with minimal configuration. For advanced settings, create `~/.koopa/config.yaml`:

```yaml
# AI model
model_name: "gemini-2.5-flash"
temperature: 0.7

# Database
postgres_host: "localhost"
postgres_db_name: "koopa"

# Knowledge base
rag_top_k: 3 # Number of relevant documents to retrieve
```

## Architecture

Koopa is built with:

- **[Genkit](https://firebase.google.com/docs/genkit/go)** - AI framework for tool integration and generation
- **PostgreSQL + pgvector** - Vector storage for semantic search
- **Wire** - Compile-time dependency injection
- **Pure Go** - Single static binary, no CGO dependencies

## Development

```bash
# Run tests
go test ./...

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o koopa-linux
GOOS=windows GOARCH=amd64 go build -o koopa.exe

# Regenerate database code (after schema changes)
sqlc generate

# Regenerate dependency injection (after changing providers)
cd internal/app && wire
```

## Contributing

Contributions welcome! Please open an issue or PR.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built with [Genkit](https://github.com/firebase/genkit)**
