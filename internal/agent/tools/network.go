package tools

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// registerNetworkTools registers network-related tools
// httpValidator is passed as parameter and captured by closures (Go best practice)
func registerNetworkTools(g *genkit.Genkit, httpValidator *security.HTTPValidator) {
	// 1. HTTP GET request (with SSRF protection)
	genkit.DefineTool(
		g, "httpGet", "Send HTTP GET request (SSRF protection enabled)",
		func(ctx *ai.ToolContext, input struct {
			URL string `json:"url" jsonschema_description:"URL to request"`
		}) (string, error) {
			// URL security validation (prevent SSRF attacks)
			if err := httpValidator.ValidateURL(input.URL); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: URL validation failed\nReason: %w\nThis may be an attempt to access internal network or metadata services", err)
			}

			// Use securely configured HTTP client (with timeout and redirect limits)
			client := httpValidator.CreateSafeHTTPClient()
			resp, err := client.Get(input.URL)
			if err != nil {
				return "", fmt.Errorf("HTTP request failed: %w", err)
			}
			defer resp.Body.Close()

			// Limit response size (prevent resource exhaustion)
			maxSize := httpValidator.GetMaxResponseSize()
			limitedReader := io.LimitReader(resp.Body, maxSize)

			body, err := io.ReadAll(limitedReader)
			if err != nil {
				return "", fmt.Errorf("failed to read response: %w", err)
			}

			// Check if size limit exceeded
			if int64(len(body)) >= maxSize {
				return "", fmt.Errorf("response size exceeds limit (max %d MB)", maxSize/(1024*1024))
			}

			result := map[string]any{
				"status": resp.StatusCode,
				"body":   string(body),
			}

			jsonResult, _ := json.Marshal(result)
			return string(jsonResult), nil
		},
	)
}
