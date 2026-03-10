package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"
)

const (
	notionBaseURL = "https://api.notion.com"
	apiVersion    = "2025-09-03"
)

// Client calls the Notion API with rate limiting.
type Client struct {
	httpClient *http.Client
	apiKey     string
	limiter    *rate.Limiter
}

// NewClient returns a Notion API client rate-limited to 3 requests per second.
func NewClient(apiKey string) *Client {
	return &Client{
		httpClient: &http.Client{},
		apiKey:     apiKey,
		limiter:    rate.NewLimiter(rate.Limit(3), 1),
	}
}

// PageResponse is the Notion page API response.
type PageResponse struct {
	ID         string                     `json:"id"`
	Archived   bool                       `json:"archived"`
	Properties map[string]json.RawMessage `json:"properties"`
}

// Block is a simplified Notion block.
type Block struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"-"`
}

// Page fetches a page by ID (GET /v1/pages/{id}).
func (c *Client) Page(ctx context.Context, pageID string) (*PageResponse, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	url := fmt.Sprintf("%s/v1/pages/%s", notionBaseURL, pageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching page %s: %w", pageID, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("notion api returned %d for page %s", resp.StatusCode, pageID)
	}

	var page PageResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decoding page %s: %w", pageID, err)
	}
	return &page, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Notion-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")
}
