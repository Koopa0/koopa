package cmd

import "fmt"

// runVersion displays version information.
func runVersion() {
	fmt.Printf("Koopa v%s\n", Version)
}

// runHelp displays the help message.
func runHelp() {
	fmt.Println("Koopa - Your terminal AI personal assistant")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  koopa cli          Start interactive chat mode")
	fmt.Println("  koopa serve [addr] Start HTTP API server (default: 127.0.0.1:3400)")
	fmt.Println("  koopa mcp          Start MCP server (for Claude Desktop/Cursor)")
	fmt.Println("  koopa --version    Show version information")
	fmt.Println("  koopa --help       Show this help")
	fmt.Println()
	fmt.Println("CLI Commands (in interactive mode):")
	fmt.Println("  /help              Show available commands")
	fmt.Println("  /version           Show version")
	fmt.Println("  /clear             Clear conversation history")
	fmt.Println("  /exit, /quit       Exit Koopa")
	fmt.Println()
	fmt.Println("Shortcuts:")
	fmt.Println("  Ctrl+D             Exit Koopa")
	fmt.Println("  Ctrl+C             Cancel current input")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  GEMINI_API_KEY     Required: Gemini API key")
	fmt.Println("  DEBUG              Optional: Enable debug logging")
	fmt.Println()
	fmt.Println("Learn more: https://github.com/koopa0/koopa")
}
