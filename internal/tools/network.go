package tools

// network.go defines HTTP request tools with SSRF protection.
//
// Provides httpGet tool for sending HTTP GET requests with comprehensive security:
//   - SSRF protection: Blocks private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x), localhost, cloud metadata endpoints (169.254.169.254)
//   - Resource limits: Response size limits (10MB default), request timeout (30s), redirect limits (10)
//   - Structured output: Returns JSON with status code and body for programmatic processing
//
// Architecture: Genkit closures act as thin adapters that convert JSON input
// to Handler method calls. Business logic lives in testable Handler methods.

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// registerNetworkTools registers network-related tools
// handler contains all business logic for network operations
func registerNetworkTools(g *genkit.Genkit, handler *Handler) {
	// 1. HTTP GET request (with SSRF protection)
	genkit.DefineTool(
		g,
		"httpGet",
		"Send an HTTP GET request to a URL with comprehensive security protection. "+
			"Security features: SSRF protection (blocks internal IPs, localhost, metadata services), response size limits, timeout protection. "+
			"Use this to fetch web content, call public APIs, retrieve remote data, or check website status. "+
			"Returns JSON with status code and response body. "+
			"Blocked: private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x), cloud metadata endpoints (169.254.169.254). "+
			"Use for: fetching public APIs, retrieving web pages, checking HTTP endpoints, downloading public data.",
		func(ctx *ai.ToolContext, input struct {
			URL string `json:"url" jsonschema_description:"Full URL to request (must start with http:// or https://). Examples: 'https://api.github.com/repos/firebase/genkit', 'https://example.com'. Private IPs and localhost are blocked."`
		},
		) (string, error) {
			return handler.HTTPGet(input.URL)
		},
	)
}
