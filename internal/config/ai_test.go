package config

import "testing"

// TestFullModelName tests that FullModelName derives correct provider-qualified names.
func TestFullModelName(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		modelName string
		want      string
	}{
		{name: "gemini default", provider: "", modelName: "gemini-2.5-flash", want: "googleai/gemini-2.5-flash"},
		{name: "gemini explicit", provider: "gemini", modelName: "gemini-2.5-pro", want: "googleai/gemini-2.5-pro"},
		{name: "ollama", provider: "ollama", modelName: "llama3.3", want: "ollama/llama3.3"},
		{name: "openai", provider: "openai", modelName: "gpt-4o", want: "openai/gpt-4o"},
		{name: "already qualified", provider: "ollama", modelName: "ollama/llama3.3", want: "ollama/llama3.3"},
		{name: "cross-qualified", provider: "gemini", modelName: "openai/gpt-4o", want: "openai/gpt-4o"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Provider:  tt.provider,
				ModelName: tt.modelName,
			}
			got := cfg.FullModelName()
			if got != tt.want {
				t.Errorf("FullModelName() = %q, want %q", got, tt.want)
			}
		})
	}
}
