![Koopa Assistant](docs/assets/koopa.png)

[Koopa](https://github.com/koopa0/koopa) is a powerful terminal-based AI assistant built on [Genkit](https://github.com/firebase/genkit), enabling you to interact with AI directly from your command line for various tasks.

## Why Koopa?

Koopa brings professional AI capabilities to your terminal with a focus on simplicity, performance, and developer experience.

## Key Features

<table>
  <tr>
    <td><strong>Pure Go Architecture</strong></td>
    <td>100% pure Go implementation with zero CGO dependencies. Single static binary for easy distribution and deployment. No need for C compilers or external dependencies. Cross-compile to Linux/Windows/macOS/ARM with one command.</td>
  </tr>
  <tr>
    <td><strong>AI-Powered Conversations</strong></td>
    <td>Streaming responses with typewriter effect for enhanced interactive experience. Structured JSON output with schema validation. Multi-modal input support for image analysis, OCR, and UI/UX evaluation (JPEG/PNG/GIF/WebP). Persistent conversation history with multi-session support using pure Go SQLite.</td>
  </tr>
  <tr>
    <td><strong>Genkit Integration</strong></td>
    <td>Full integration with Firebase Genkit framework including 9 AI Flows for personal assistance workflows: chat, analysis, email composition, topic research, task planning, code review, and more. MCP (Model Context Protocol) support for connecting external tool servers. Built-in RAG (Retrieval-Augmented Generation) with vector embeddings and semantic search.</td>
  </tr>
  <tr>
    <td><strong>Powerful Tool System</strong></td>
    <td>9 local tools with security validation: file operations, system commands, HTTP requests, environment variables, and more. Dotprompt support for flexible prompt management. OpenTelemetry integration for observability with tracing and metrics.</td>
  </tr>
  <tr>
    <td><strong>Multi-Language Support</strong></td>
    <td>Built-in i18n system supporting English and Traditional Chinese (繁體中文), with Japanese (日本語) reserved for future releases. Switch languages via <code>--lang</code> flag or <code>KOOPA_LANG</code> environment variable. Runtime language switching with <code>/lang</code> command in chat mode.</td>
  </tr>
  <tr>
    <td><strong>Developer-Friendly</strong></td>
    <td>Clean command-line interface with Cobra framework. Comprehensive error handling and security validation. Environment variable support with <code>KOOPA_*</code> prefix. Optional YAML configuration file for persistent settings.</td>
  </tr>
</table>

## How Does It Work?

Koopa leverages the Genkit framework to provide a seamless AI experience directly in your terminal. It manages conversation context, executes tool calls securely, and maintains persistent session history.

Key capabilities:

- **Streaming Chat**: Real-time typewriter effect for AI responses
- **Tool Execution**: Securely execute file operations, system commands, and HTTP requests
- **Session Management**: Persistent conversation history across sessions
- **Flow Execution**: Run predefined AI workflows for common tasks
- **Multi-Modal**: Analyze images and documents with AI
- **Extensible**: Add custom tools and flows using Genkit's framework

## Implementation Path

<table>
<tr>
  <td><span>1</span></td>
  <td>Install Go and get Gemini API Key</td>
  <td>Ensure you have Go 1.25+ installed. Get your free Gemini API key from <a href="https://ai.google.dev/">ai.google.dev</a>.</td>
</tr>
<tr>
  <td><span>2</span></td>
  <td>Clone and build Koopa</td>
  <td>Clone the repository and build the single static binary using <code>go build</code>. No CGO or external dependencies required.</td>
</tr>
<tr>
  <td><span>3</span></td>
  <td>Configure API key</td>
  <td>Set your Gemini API key using the <code>KOOPA_GEMINI_API_KEY</code> environment variable or configuration file.</td>
</tr>
<tr>
  <td><span>4</span></td>
  <td>Start chatting</td>
  <td>Run <code>./koopa</code> to enter interactive chat mode, or use <code>./koopa ask "your question"</code> for one-off queries. Enable tools with <code>/tools</code> or <code>--tools</code> flag for enhanced capabilities.</td>
</tr>
</table>

## Get Started

### Prerequisites

- Go 1.25 or higher
- Gemini API Key ([Get one free](https://ai.google.dev/))

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/koopa0/koopa.git
cd koopa

# 2. Build (100% pure Go, no CGO)
go build -o koopa

# 3. Set your API key
export KOOPA_GEMINI_API_KEY=your-api-key-here

# 4. Start using Koopa
./koopa
```

## Usage

### Interactive Chat Mode (Most Common)

Simply run `koopa` to enter chat mode:

```bash
$ ./koopa
Welcome to Koopa v0.1.0 - Your terminal AI personal assistant
Type /help for commands, Ctrl+D or /exit to quit
Session ID: 1

You> Hello
Koopa> Hello! How can I help you today?

You> /tools
🔧 Tools enabled
   Available tools:
   - currentTime      Get current time
   - readFile         Read file contents
   - writeFile        Write content to file
   - listFiles        List directory contents
   - deleteFile       Delete a file
   - executeCommand   Execute system command
   - httpGet          HTTP GET request
   - getEnv           Read environment variable
   - getFileInfo      Get file information

You> What time is it now?
Koopa> It's currently October 23, 2025, 12:30 PM.

You> /exit
Goodbye!
```

#### Chat Mode Special Commands

- `/help` - Show help message
- `/tools` - Toggle tools on/off
- `/clear` - Clear chat history
- `/lang <code>` - Change language (en, zh-TW)
- `/exit` or `/quit` - Exit chat
- `Ctrl+D` - Exit chat

### Single Question Mode

Ask a question without entering chat mode:

```bash
# Basic question
./koopa ask "Explain what Go language is in one sentence"

# With tools enabled
./koopa ask --tools "Read README.md and summarize key points"
./koopa ask --tools "What time is it now?"
```

### Language Support

Koopa supports multiple languages with easy switching:

```bash
# Use English (default)
./koopa

# Use Traditional Chinese
./koopa --lang zh-TW
# or
export KOOPA_LANG=zh-TW
./koopa

# Switch language in chat
You> /lang zh-TW
Language changed to: zh-TW

You> /lang en
Language changed to: en
```

### Using Genkit Flows

Koopa provides 9 predefined AI workflows covering conversation, content creation, research, productivity, and development assistance:

```bash
# Start Genkit Developer UI
genkit start -- go run main.go

# Core conversations
genkit flow:run chat '"Hello"' -s                                             # Streaming chat

# Analysis (unified entry point, supports file/log/document/text)
genkit flow:run analyze '{"content":"main.go","content_type":"file"}'        # File analysis
genkit flow:run analyze '{"content":"app.log","content_type":"log"}'         # Log analysis
genkit flow:run analyze '{"content":"README.md","content_type":"document"}'  # Document analysis

# Content creation
genkit flow:run composeEmail '{"recipient":"colleague","purpose":"thanks","context":"help with project"}'

# Research & information
genkit flow:run researchTopic '{"topic":"Genkit framework best practices"}'

# Productivity
genkit flow:run planTasks '{"goal":"Complete API development","deadline":"Friday"}'

# Development assistance
genkit flow:run reviewCode '"internal/agent/agent.go"'
genkit flow:run suggestCommand '"list all Go files"'
genkit flow:run generateCommitMessage '"git diff output"'
genkit flow:run diagnoseError '"error: not found"'
```

### View Information

```bash
# View version and configuration
./koopa version

# List all available flows
genkit flow:list
```

## Configuration

### Environment Variables (Recommended)

Use `KOOPA_` prefix to avoid naming conflicts:

```bash
export KOOPA_GEMINI_API_KEY=your-api-key-here
export KOOPA_MODEL_NAME=gemini-2.5-pro      # Optional
export KOOPA_TEMPERATURE=0.8                 # Optional
export KOOPA_MAX_TOKENS=4096                 # Optional
export KOOPA_MAX_HISTORY_MESSAGES=100        # Optional
export KOOPA_LANG=en                         # Optional (en, zh-TW)
```

**Environment Variable Priority**: `KOOPA_*` > Configuration file > Default values

### Configuration File (Optional)

Create `~/.koopa/config.yaml`:

```yaml
# AI model settings
model_name: "gemini-2.5-flash"
temperature: 0.7
max_tokens: 2048

# Conversation history configuration (default 50 messages, ~25 conversation turns)
# Sliding window mechanism enabled to prevent excessive token consumption
max_history_messages: 50
# Database path (defaults to ~/.koopa/koopa.db)
# database_path: "/path/to/koopa.db"

# API Key (recommended to use environment variable instead)
# gemini_api_key: "your-api-key-here"
```

## Available Tools

Koopa comes with 9 built-in tools with security validation:

1. **currentTime** - Get current system time
2. **readFile** - Read file contents with path validation
3. **writeFile** - Write content to file with safety checks
4. **listFiles** - List directory contents
5. **deleteFile** - Delete files with confirmation
6. **executeCommand** - Execute system commands (with dangerous command blocking)
7. **httpGet** - Make HTTP GET requests (with internal network protection)
8. **getEnv** - Read environment variables (with sensitive variable protection)
9. **getFileInfo** - Get file metadata and information

All tools include comprehensive security validation to protect your system.

## Documentation

For detailed documentation about the Genkit framework and Koopa's architecture:

- [Genkit Official Documentation](https://docs/README.md) - Index of all technical documentation
- [Genkit Go Documentation](https://firebase.google.com/docs/genkit/go)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)

## Development

### Building from Source

```bash
# Build for current platform
go build -o koopa

# Build for Linux AMD64
GOOS=linux GOARCH=amd64 go build -o koopa-linux-amd64

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o koopa-windows.exe

# Build for macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o koopa-darwin-arm64
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/agent/
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contact

Have questions or suggestions? Feel free to open an issue on GitHub.

---

**Made with [Genkit](https://github.com/firebase/genkit)**
