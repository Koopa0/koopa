package tools

import (
	"fmt"
	"io"
	"net/http"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/log"
)

// NetworkToolsetName is the toolset identifier constant.
const NetworkToolsetName = "network"

// HTTPGetInput defines input for httpGet tool.
type HTTPGetInput struct {
	URL string `json:"url" jsonschema_description:"The URL to fetch"`
}

// httpValidator defines the HTTP validation behavior required by NetworkToolset.
// This is an unexported internal interface following Go best practices.
type httpValidator interface {
	ValidateURL(url string) error
	Client() *http.Client
	MaxResponseSize() int64
}

// NetworkToolset provides network operation tools with built-in security protections.
// It implements the Toolset interface and offers the following tools:
//   - httpGet: Sends HTTP GET requests with SSRF protection
//
// Security features:
//   - SSRF protection: Blocks private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x), localhost, and cloud metadata endpoints
//   - Resource limits: Response size limit (10MB default), request timeout (30s), redirect limit (10)
type NetworkToolset struct {
	httpVal httpValidator
	logger  log.Logger
}

// NewNetworkToolset creates a new NetworkToolset with HTTP validation.
func NewNetworkToolset(httpVal httpValidator, logger log.Logger) (*NetworkToolset, error) {
	if httpVal == nil {
		return nil, fmt.Errorf("http validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &NetworkToolset{
		httpVal: httpVal,
		logger:  logger,
	}, nil
}

// Name returns the toolset identifier.
func (nt *NetworkToolset) Name() string {
	return NetworkToolsetName
}

// Tools returns all network operation tools provided by this toolset.
func (nt *NetworkToolset) Tools(ctx agent.ReadonlyContext) ([]Tool, error) {
	return []Tool{
		NewTool(
			"httpGet",
			"Send an HTTP GET request to a URL. Includes SSRF protection (blocks private IPs, localhost, cloud metadata).",
			true, // long running
			nt.HTTPGet,
		),
	}, nil
}

// Output type definitions follow.

// HTTPGetOutput is the output for httpGet tool
type HTTPGetOutput struct {
	URL    string `json:"url" jsonschema:"description=The requested URL"`
	Status int    `json:"status" jsonschema:"description=HTTP status code"`
	Body   string `json:"body" jsonschema:"description=Response body"`
}

// HTTPGet sends an HTTP GET request to a URL with SSRF protection.
// Blocks requests to private IPs, localhost, and cloud metadata endpoints.
func (nt *NetworkToolset) HTTPGet(ctx *ai.ToolContext, input HTTPGetInput) (Result, error) {
	nt.logger.Info("HTTPGet called", "url", input.URL)

	// URL security validation (prevent SSRF attacks)
	if err := nt.httpVal.ValidateURL(input.URL); err != nil {
		nt.logger.Error("HTTPGet URL validation failed", "url", input.URL, "error", err)
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
	client := nt.httpVal.Client()
	resp, err := client.Get(input.URL)
	if err != nil {
		nt.logger.Error("HTTPGet request failed", "url", input.URL, "error", err)
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
	maxSize := nt.httpVal.MaxResponseSize()
	limitedReader := io.LimitReader(resp.Body, maxSize)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		nt.logger.Error("HTTPGet read failed", "url", input.URL, "error", err)
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
			nt.logger.Error("HTTPGet response too large", "url", input.URL, "max_size", maxSize)
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
	nt.logger.Info("HTTPGet succeeded", "url", input.URL, "status_code", resp.StatusCode, "body_size", len(body))
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
