package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa/internal/security"
)

const (
	// NotionAPIBase is the base URL for Notion API.
	NotionAPIBase = "https://api.notion.com"
	// NotionAPIVersion is the API version header value.
	NotionAPIVersion = "2022-06-28"
)

// Client is a lightweight Notion API client.
// It uses security.HTTPValidator to ensure all requests are safe.
type Client struct {
	token         string
	httpValidator *security.HTTPValidator
	httpClient    *http.Client
}

// New creates a new Notion API client.
//
// Parameters:
//   - token: Notion integration token (format: "ntn_***")
//   - httpValidator: Security validator for HTTP requests (required)
//
// Returns:
//   - *Client: Initialized client
//   - error: If token is empty or httpValidator is nil
func New(token string, httpValidator *security.HTTPValidator) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("notion token is required")
	}
	if httpValidator == nil {
		return nil, fmt.Errorf("http validator is required")
	}

	return &Client{
		token:         token,
		httpValidator: httpValidator,
		httpClient:    httpValidator.CreateSafeHTTPClient(),
	}, nil
}

// Search searches for all pages accessible to the integration.
//
// Parameters:
//   - ctx: Context for the request
//   - query: Search query (empty string returns all pages)
//
// Returns:
//   - []Page: List of pages matching the query
//   - error: If request fails
//
// This method automatically handles pagination and retrieves all results.
func (c *Client) Search(ctx context.Context, query string) ([]Page, error) {
	var allPages []Page
	startCursor := ""

	for {
		req := SearchRequest{
			Query: query,
			Filter: &SearchFilter{
				Property: "object",
				Value:    "page",
			},
			PageSize: 100, // Maximum allowed by Notion API
		}

		if startCursor != "" {
			req.StartCursor = startCursor
		}

		resp, err := c.search(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}

		// Extract pages from results (filter out databases)
		for _, rawResult := range resp.Results {
			// First, check object type
			var objCheck struct {
				Object string `json:"object"`
			}
			if err := json.Unmarshal(rawResult, &objCheck); err != nil {
				slog.Warn("failed to check result object type",
					"error", err)
				continue
			}

			// Only process pages (skip databases)
			if objCheck.Object != "page" {
				continue
			}

			// Parse as Page
			var page Page
			if err := json.Unmarshal(rawResult, &page); err != nil {
				slog.Warn("failed to parse page from search result",
					"error", err)
				continue
			}
			allPages = append(allPages, page)
		}

		// Check if there are more results
		if !resp.HasMore {
			break
		}
		startCursor = resp.NextCursor
	}

	slog.Info("notion search completed",
		"query", query,
		"page_count", len(allPages))

	return allPages, nil
}

// search performs a single search request (internal helper).
func (c *Client) search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	url := NotionAPIBase + "/v1/search"

	var resp SearchResponse
	if err := c.makeRequest(ctx, "POST", url, req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetBlockChildren retrieves all child blocks of a given block.
//
// Parameters:
//   - ctx: Context for the request
//   - blockID: ID of the parent block (can be a page ID)
//
// Returns:
//   - []Block: List of child blocks
//   - error: If request fails
//
// This method automatically handles pagination and recursively retrieves
// all nested blocks.
func (c *Client) GetBlockChildren(ctx context.Context, blockID string) ([]Block, error) {
	var allBlocks []Block
	startCursor := ""

	for {
		url := fmt.Sprintf("%s/v1/blocks/%s/children", NotionAPIBase, blockID)
		if startCursor != "" {
			url += "?start_cursor=" + startCursor
		}

		var resp BlockChildrenResponse
		if err := c.makeRequest(ctx, "GET", url, nil, &resp); err != nil {
			return nil, fmt.Errorf("get block children failed: %w", err)
		}

		allBlocks = append(allBlocks, resp.Results...)

		// Check if there are more results
		if !resp.HasMore {
			break
		}
		startCursor = resp.NextCursor
	}

	// Recursively retrieve nested blocks
	var blocksWithChildren []Block
	for _, block := range allBlocks {
		blocksWithChildren = append(blocksWithChildren, block)

		if block.HasChildren {
			children, err := c.GetBlockChildren(ctx, block.ID)
			if err != nil {
				slog.Warn("failed to retrieve nested blocks",
					"block_id", block.ID,
					"error", err)
				continue
			}
			blocksWithChildren = append(blocksWithChildren, children...)
		}
	}

	return blocksWithChildren, nil
}

// GetPage retrieves a page by ID.
//
// Parameters:
//   - ctx: Context for the request
//   - pageID: ID of the page
//
// Returns:
//   - *Page: The page object
//   - error: If request fails
func (c *Client) GetPage(ctx context.Context, pageID string) (*Page, error) {
	url := fmt.Sprintf("%s/v1/pages/%s", NotionAPIBase, pageID)

	var page Page
	if err := c.makeRequest(ctx, "GET", url, nil, &page); err != nil {
		return nil, fmt.Errorf("get page failed: %w", err)
	}

	return &page, nil
}

// makeRequest is a helper method to make HTTP requests to Notion API.
//
// Parameters:
//   - ctx: Context for the request
//   - method: HTTP method (GET, POST, etc.)
//   - url: Full URL to request
//   - body: Request body (nil for GET requests)
//   - result: Pointer to store the response
//
// Returns:
//   - error: If request fails or security validation fails
func (c *Client) makeRequest(ctx context.Context, method, url string, body, result any) error {
	// Validate URL using security validator
	if err := c.httpValidator.ValidateURL(url); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	// Prepare request body
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Notion-Version", NotionAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notion API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// Unmarshal response
	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
