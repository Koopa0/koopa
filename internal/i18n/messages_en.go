package i18n

// loadEnglishMessages loads all English translations
func loadEnglishMessages() {
	messages[LangEN] = map[string]string{
		// Common
		"app.name":        "Koopa",
		"app.description": "Your terminal AI personal assistant",
		"app.version":     "Koopa v%s",

		// Welcome and Exit
		"welcome":       "Welcome to Koopa v%s - Your terminal AI personal assistant",
		"welcome.help":  "Type /help for commands, Ctrl+D or /exit to quit",
		"goodbye":       "Goodbye!",
		"exit":          "Exiting...",

		// Chat commands
		"chat.prompt":          "You> ",
		"chat.assistant":       "Koopa> ",
		"chat.tools.enabled":   "🔧 Tools enabled",
		"chat.tools.disabled":  "🔧 Tools disabled",
		"chat.tools.available": "   Available tools:",
		"chat.tool.item":       "   - %-15s %s",
		"chat.cleared":         "✨ Chat history cleared",
		"chat.streaming.error": "Streaming error: %v",

		// Help messages
		"help.title":          "Available Commands:",
		"help.help":           "/help              Show this help message",
		"help.tools":          "/tools             Toggle tools on/off",
		"help.clear":          "/clear             Clear chat history",
		"help.exit":           "/exit or /quit     Exit the chat",
		"help.lang":           "/lang <code>       Change language (en, zh-TW)",
		"help.ctrl_d":         "Ctrl+D             Exit the chat",
		"help.current.lang":   "\nCurrent language: %s",
		"help.available.lang": "Available languages: %s",

		// Language
		"lang.changed":     "Language changed to: %s",
		"lang.unsupported": "Unsupported language: %s",
		"lang.available":   "Available languages: %s",
		"lang.current":     "Current language: %s",

		// Errors
		"error.input":          "Error reading input: %v",
		"error.generate":       "Error generating response: %v",
		"error.config":         "Error loading config: %v",
		"error.agent":          "Error creating agent: %v",
		"error.memory":         "Error initializing memory: %v",
		"error.database":       "Error initializing database: %v",
		"error.session":        "Error creating session: %v",
		"error.message":        "Error saving message: %v",
		"error.question.empty": "Question cannot be empty",

		// Session management
		"session.list.title":  "Available Sessions:",
		"session.list.item":   "  [%d] %s (Created: %s, Updated: %s)",
		"session.list.empty":  "No sessions found",
		"session.delete.ok":   "Session %d deleted successfully",
		"session.delete.fail": "Failed to delete session: %v",

		// Ask command
		"ask.description": "Ask a single question to Koopa",
		"ask.question":    "Question to ask",
		"ask.tools.flag":  "Enable tools for this question",

		// Chat command
		"chat.description":      "Start an interactive chat session with Koopa",
		"chat.session.flag":     "Session ID to continue (optional)",
		"chat.tools.flag":       "Enable tools by default",
		"chat.session.creating": "Creating new session...",
		"chat.session.loading":  "Loading session %d...",

		// Sessions command
		"sessions.description":        "Manage chat sessions",
		"sessions.list.description":   "List all sessions",
		"sessions.delete.description": "Delete a session",
		"sessions.delete.id":          "Session ID to delete",

		// Version command
		"version.description": "Show version information",
		"version.info":        "Koopa v%s\nBuild date: %s\nGit commit: %s",

		// Config
		"config.model":       "Model: %s",
		"config.temperature": "Temperature: %.2f",
		"config.max.tokens":  "Max tokens: %d",

		// Tool names and descriptions (from tools.go)
		"tool.currentTime.name":       "currentTime",
		"tool.currentTime.desc":       "Get current time",
		"tool.readFile.name":          "readFile",
		"tool.readFile.desc":          "Read file contents",
		"tool.writeFile.name":         "writeFile",
		"tool.writeFile.desc":         "Write content to file",
		"tool.listFiles.name":         "listFiles",
		"tool.listFiles.desc":         "List directory contents",
		"tool.deleteFile.name":        "deleteFile",
		"tool.deleteFile.desc":        "Delete a file",
		"tool.executeCommand.name":    "executeCommand",
		"tool.executeCommand.desc":    "Execute system command",
		"tool.httpGet.name":           "httpGet",
		"tool.httpGet.desc":           "HTTP GET request",
		"tool.getEnv.name":            "getEnv",
		"tool.getEnv.desc":            "Read environment variable",
		"tool.getFileInfo.name":       "getFileInfo",
		"tool.getFileInfo.desc":       "Get file information",

		// Security warnings (from security validators)
		"security.path.invalid":         "⚠️  Security warning: Path validation failed\nReason: %w",
		"security.command.dangerous":    "⚠️  Security warning: Dangerous command rejected\nCommand: %s %s\nReason: %w\nIf you need to execute this, please run it manually in terminal",
		"security.url.invalid":          "⚠️  Security warning: URL validation failed\nReason: %w\nThis may be an attempt to access internal network or metadata services",
		"security.env.restricted":       "⚠️  Security warning: %w\nHint: This environment variable may contain sensitive information and is protected.\nIf you need to access it, please check it directly in terminal",

		// Root command
		"root.description": "Koopa - Your terminal AI personal assistant powered by Genkit",
		"root.lang.flag":   "Language (en, zh-TW)",
	}
}
