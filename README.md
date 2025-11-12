# Koopa CLI

![Koopa Assistant](docs/assets/Koopa-CLI.jpg)

**A terminal-based AI assistant with knowledge base capabilities, built on [Genkit](https://github.com/firebase/genkit).**

Koopa brings AI conversations directly to your command line with the ability to index and search your local documents for context-aware responses.

## Why Koopa?

- **Smart Knowledge Base** - Index your documents and let Koopa remember them for you
- **Private & Local** - Your data stays on your machine, stored in local PostgreSQL
- **Extensible Tools** - Built-in file operations, system commands, and HTTP requests
- **MCP Compatible** - Add custom tools via [Model Context Protocol](https://modelcontextprotocol.io/)
- **Single Binary** - Pure Go implementation, no runtime dependencies
- **Powered by Genkit** - Built on Firebase's [Genkit framework](https://github.com/firebase/genkit)

## Installation

**Prerequisites:** Go 1.24 +, Docker & Docker Compose, and a [Gemini API key](https://ai.google.dev/)

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

## Getting Started

### Basic Chat

```bash
$ ./koopa
Version: 1.0

> What is the capital of France?
Paris is the capital of France.

> /exit
```

### Knowledge Base (RAG)

Index your documents and ask questions about them:

```bash
> /rag add ~/Documents/notes/

> /rag list
Indexed Documents (3):
- meeting-notes.md (2KB)
- project-ideas.txt (1KB)
- research.md (5KB)

> What were the action items from my last meeting?
Based on your meeting notes, the action items were:
1. Follow up with the design team
2. Schedule Q2 planning session
3. Review the budget proposal
```

## Features

### Interactive Chat

Start conversations with Gemini right from your terminal:

```bash
> Tell me a joke about programming
> Explain how binary search works
> Help me debug this error message
```

### Knowledge Base (RAG)

Index your local documents and have Koopa reference them in conversations:

```bash
> /rag add ~/Documents/         # Index a directory
> /rag add ./project/README.md  # Index a single file
> /rag list                     # View all indexed content
> /rag status                   # Check system status
```

### Built-in Tools

Koopa can help you with:

- **File Operations** - Read, write, and manipulate files
- **System Commands** - Execute shell commands
- **Network Requests** - Make HTTP requests and fetch web content

### Extensible via MCP

Add custom tools using the [Model Context Protocol](https://modelcontextprotocol.io/) to extend Koopa's capabilities.

## Commands

| Command            | Description                         |
| ------------------ | ----------------------------------- |
| `/help`            | Show available commands             |
| `/version`         | Show version information            |
| `/rag add <path>`  | Index files or directories          |
| `/rag list`        | List indexed documents              |
| `/rag remove <id>` | Remove document from knowledge base |
| `/rag status`      | Show RAG status and statistics      |
| `/clear`           | Clear current conversation          |
| `/exit` or `/quit` | Exit Koopa                          |

**Shortcuts:**

- `Ctrl+D` - Exit Koopa
- `Ctrl+C` - Cancel current input

## Configuration

Koopa works with minimal configuration. Set your API key and you're ready to go:

```bash
export GEMINI_API_KEY=your-api-key
./koopa
```

For advanced settings, create `~/.koopa/config.yaml`:

```yaml
# AI model
model_name: "gemini-2.5-flash" # or "gemini-2.5-pro"
temperature: 0.7
max_tokens: 2048

# Database (using docker-compose defaults)
postgres_host: "localhost"
postgres_port: 5432
postgres_user: "koopa"
postgres_password: "koopa_dev_password"
postgres_db_name: "koopa"

# Knowledge base
rag_top_k: 3 # Number of relevant documents to retrieve
embedder_model: "text-embedding-004" # Google AI embedder

# Conversation
max_history_messages: 50 # Keep recent 50 messages
```

## Technology

Koopa is built with:

- **[Genkit](https://firebase.google.com/docs/genkit/go)** - AI framework for tool integration
- **PostgreSQL + pgvector** - Vector storage for semantic search
- **Pure Go** - Single static binary, no runtime dependencies

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue on [GitHub](https://github.com/koopa0/koopa-cli).

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built using [Genkit](https://github.com/firebase/genkit)**
