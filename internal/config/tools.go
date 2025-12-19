package config

import (
	"encoding/json"
	"fmt"
)

// MCPConfig controls global MCP (Model Context Protocol) behavior.
type MCPConfig struct {
	Allowed  []string `mapstructure:"allowed" json:"allowed"`   // Whitelist of server names (empty = all configured servers)
	Excluded []string `mapstructure:"excluded" json:"excluded"` // Blacklist of server names (higher priority than Allowed)
	Timeout  int      `mapstructure:"timeout" json:"timeout"`   // Connection timeout in seconds (default: 5)
}

// MCPServer defines a single MCP server configuration.
type MCPServer struct {
	Command      string            `mapstructure:"command" json:"command"`             // Required: executable path (e.g., "npx")
	Args         []string          `mapstructure:"args" json:"args"`                   // Optional: command arguments
	Env          map[string]string `mapstructure:"env" json:"env"`                     // Optional: environment variables - SECURITY: May contain API keys/tokens
	Timeout      int               `mapstructure:"timeout" json:"timeout"`             // Optional: per-server timeout (overrides global)
	IncludeTools []string          `mapstructure:"include_tools" json:"include_tools"` // Optional: tool whitelist
	ExcludeTools []string          `mapstructure:"exclude_tools" json:"exclude_tools"` // Optional: tool blacklist
}

// MarshalJSON implements json.Marshaler with sensitive field masking.
// Masks all values in the Env map as they may contain API keys/tokens.
func (m MCPServer) MarshalJSON() ([]byte, error) {
	type alias MCPServer
	a := alias(m)
	if a.Env != nil {
		maskedEnv := make(map[string]string, len(a.Env))
		for k, v := range a.Env {
			maskedEnv[k] = maskSecret(v)
		}
		a.Env = maskedEnv
	}
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal mcp server: %w", err)
	}
	return data, nil
}

// SearXNGConfig holds SearXNG service configuration for web search.
type SearXNGConfig struct {
	// BaseURL is the SearXNG instance URL (e.g., http://searxng:8080)
	BaseURL string `mapstructure:"base_url" json:"base_url"`
}

// WebScraperConfig holds web scraper configuration for web fetching.
type WebScraperConfig struct {
	// Parallelism is max concurrent requests per domain (default: 2)
	Parallelism int `mapstructure:"parallelism" json:"parallelism"`
	// DelayMs is delay between requests in milliseconds (default: 1000)
	DelayMs int `mapstructure:"delay_ms" json:"delay_ms"`
	// TimeoutMs is request timeout in milliseconds (default: 30000)
	TimeoutMs int `mapstructure:"timeout_ms" json:"timeout_ms"`
}
