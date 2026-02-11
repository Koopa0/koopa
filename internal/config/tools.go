package config

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
