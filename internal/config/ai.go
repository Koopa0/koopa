package config

// AIConfig holds AI model configuration.
// Fields are embedded in the main Config struct for backward compatibility.
// Documented separately for clarity.
//
// Configuration options:
//   - Provider: AI provider ("gemini", "ollama", "openai")
//   - ModelName: Model identifier (e.g., "gemini-2.5-flash", "llama3.3", "gpt-4o")
//   - Temperature: 0.0 (deterministic) to 2.0 (creative)
//   - MaxTokens: 1 to 2,097,152 (Gemini 2.5 max context)
//   - Language: Response language ("auto", "English", "zh-TW")
//   - PromptDir: Directory for .prompt files (Dotprompt)
//   - OllamaHost: Ollama server address (default: "http://localhost:11434")
