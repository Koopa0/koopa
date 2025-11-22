package tools

// network.go defines HTTP request tools with SSRF protection.
//
// Provides httpGet tool for sending HTTP GET requests with comprehensive security:
//   - SSRF protection: Blocks private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x), localhost, cloud metadata endpoints (169.254.169.254)
//   - Resource limits: Response size limits (10MB default), request timeout (30s), redirect limits (10)
//   - Structured output: Returns JSON with status code and body for programmatic processing

import (
	"fmt"
	"io"

	"github.com/firebase/genkit/go/ai"
)

// ============================================================================
// Kit Methods (Phase 1 - New Architecture)
// ============================================================================

// HTTPGet sends an HTTP GET request to a URL with SSRF protection.
//
// Error handling:
//   - Agent Error (SSRF blocked, network failed, response too large): Return Result{Error: ...}, nil
//   - System Error (internal failure): Return Result{}, error (rare)
func (k *Kit) HTTPGet(ctx *ai.ToolContext, input HTTPGetInput) (Result, error) {
	k.log("info", "HTTPGet called", "url", input.URL)

	// URL security validation (prevent SSRF attacks)
	if err := k.httpVal.ValidateURL(input.URL); err != nil {
		k.log("error", "HTTPGet URL validation failed", "url", input.URL, "error", err)
		return Result{
			Status:  StatusError,
			Message: "URL validation failed",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("security warning: url validation failed (possible SSRF attempt): %v", err),
			},
		}, nil
	}

	// Use reusable HTTP client (with connection pooling and security config)
	client := k.httpVal.Client()
	resp, err := client.Get(input.URL)
	if err != nil {
		k.log("error", "HTTPGet request failed", "url", input.URL, "error", err)
		return Result{
			Status:  StatusError,
			Message: "HTTP request failed",
			Error: &Error{
				Code:    ErrCodeNetwork,
				Message: fmt.Sprintf("http request failed: %v", err),
			},
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Limit response size (prevent resource exhaustion)
	maxSize := k.httpVal.MaxResponseSize()
	limitedReader := io.LimitReader(resp.Body, maxSize)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		k.log("error", "HTTPGet read failed", "url", input.URL, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Failed to read response",
			Error: &Error{
				Code:    ErrCodeIO,
				Message: fmt.Sprintf("failed to read response: %v", err),
			},
		}, nil
	}

	// Check if size limit exceeded by trying to read one more byte
	if int64(len(body)) == maxSize {
		extra := make([]byte, 1)
		n, _ := resp.Body.Read(extra)
		if n > 0 {
			k.log("error", "HTTPGet response too large", "url", input.URL, "max_size", maxSize)
			return Result{
				Status:  StatusError,
				Message: "Response size exceeds limit",
				Error: &Error{
					Code:    ErrCodeIO,
					Message: fmt.Sprintf("response size exceeds limit (max %d MB)", maxSize/(1024*1024)),
				},
			}, nil
		}
	}

	// Success
	k.log("info", "HTTPGet succeeded", "url", input.URL, "status_code", resp.StatusCode, "body_size", len(body))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully fetched: %s (status %d)", input.URL, resp.StatusCode),
		Data: map[string]any{
			"url":    input.URL,
			"status": resp.StatusCode,
			"body":   string(body),
		},
	}, nil
}
