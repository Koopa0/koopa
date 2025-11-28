package config

// MCPConfig controls global MCP (Model Context Protocol) behavior.
type MCPConfig struct {
	Allowed  []string `mapstructure:"allowed"`  // Whitelist of server names (empty = all configured servers)
	Excluded []string `mapstructure:"excluded"` // Blacklist of server names (higher priority than Allowed)
	Timeout  int      `mapstructure:"timeout"`  // Connection timeout in seconds (default: 5)
}

// MCPServer defines a single MCP server configuration.
type MCPServer struct {
	Command      string            `mapstructure:"command"`              // Required: executable path (e.g., "npx")
	Args         []string          `mapstructure:"args"`                 // Optional: command arguments
	Env          map[string]string `mapstructure:"env" sensitive:"true"` // Optional: environment variables (supports $VAR_NAME syntax) - SECURITY: May contain API keys/tokens
	Timeout      int               `mapstructure:"timeout"`              // Optional: per-server timeout (overrides global)
	IncludeTools []string          `mapstructure:"include_tools"`        // Optional: tool whitelist
	ExcludeTools []string          `mapstructure:"exclude_tools"`        // Optional: tool blacklist
}

// SearXNGConfig holds SearXNG service configuration for web search.
type SearXNGConfig struct {
	// BaseURL is the SearXNG instance URL (e.g., http://searxng:8080)
	BaseURL string `mapstructure:"base_url"`
}

// WebScraperConfig holds web scraper configuration for web fetching.
type WebScraperConfig struct {
	// Parallelism is max concurrent requests per domain (default: 2)
	Parallelism int `mapstructure:"parallelism"`
	// DelayMs is delay between requests in milliseconds (default: 1000)
	DelayMs int `mapstructure:"delay_ms"`
	// TimeoutMs is request timeout in milliseconds (default: 30000)
	TimeoutMs int `mapstructure:"timeout_ms"`
}
