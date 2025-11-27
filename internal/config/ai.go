package config

import "github.com/firebase/genkit/go/plugins/googlegenai"

// AIConfig holds AI model configuration.
// Fields are embedded in the main Config struct for backward compatibility.
// Documented separately for clarity.
//
// Configuration options:
//   - ModelName: Gemini model identifier (e.g., "gemini-2.5-flash", "gemini-2.5-pro")
//   - Temperature: 0.0 (deterministic) to 2.0 (creative)
//   - MaxTokens: 1 to 2,097,152 (Gemini 2.5 max context)
//   - Language: Response language ("auto", "English", "zh-TW")
//   - PromptDir: Directory for .prompt files (Dotprompt)

// Plugins returns Genkit plugins for this configuration.
func (c *Config) Plugins() []any {
	return []any{&googlegenai.GoogleAI{}}
}
