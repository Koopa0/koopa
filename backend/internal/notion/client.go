package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

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
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiKey:     apiKey,
		limiter:    rate.NewLimiter(rate.Limit(3), 1),
	}
}

// PageResponse is the Notion page API response.
type PageResponse struct {
	ID         string                     `json:"id"`
	Archived   bool                       `json:"archived"`
	InTrash    bool                       `json:"in_trash"`
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
		_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
		return nil, fmt.Errorf("notion api returned %d for page %s", resp.StatusCode, pageID)
	}

	var page PageResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decoding page %s: %w", pageID, err)
	}
	return &page, nil
}

// DatabaseQueryResult holds a single page from a database query response.
type DatabaseQueryResult struct {
	ID         string                     `json:"id"`
	Properties map[string]json.RawMessage `json:"properties"`
}

// databaseQueryResponse is the Notion database query API response.
type databaseQueryResponse struct {
	Results    []DatabaseQueryResult `json:"results"`
	HasMore    bool                  `json:"has_more"`
	NextCursor *string               `json:"next_cursor"`
}

// QueryDataSource queries a Notion data source with an optional filter.
// Uses the 2025-09-03 endpoint: POST /v1/data_sources/{data_source_id}/query.
func (c *Client) QueryDataSource(ctx context.Context, dataSourceID string, filter json.RawMessage) ([]DatabaseQueryResult, error) {
	var allResults []DatabaseQueryResult
	var cursor *string

	for {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		body := map[string]any{
			"page_size": 100,
			"in_trash":  false,
			"archived":  false,
		}
		if filter != nil {
			body["filter"] = json.RawMessage(filter)
		}
		if cursor != nil {
			body["start_cursor"] = *cursor
		}

		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling query body: %w", err)
		}

		endpoint := fmt.Sprintf("%s/v1/data_sources/%s/query", notionBaseURL, dataSourceID)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("creating query request: %w", err)
		}
		c.setHeaders(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("querying data source %s: %w", dataSourceID, err)
		}

		// Decode before status check: body is consumed regardless, avoiding a separate drain step.
		// If decode fails on an error response, the status error below takes precedence.
		var qr databaseQueryResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&qr)
		resp.Body.Close() //nolint:errcheck,gosec // best-effort close on read-only HTTP response
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("notion api returned %d for data source query %s", resp.StatusCode, dataSourceID)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("decoding data source query response: %w", decodeErr)
		}

		allResults = append(allResults, qr.Results...)

		if !qr.HasMore || qr.NextCursor == nil {
			break
		}
		cursor = qr.NextCursor
	}

	return allResults, nil
}

// QueryPageIDs queries a data source and returns just the page IDs.
func (c *Client) QueryPageIDs(ctx context.Context, dataSourceID string) ([]string, error) {
	results, err := c.QueryDataSource(ctx, dataSourceID, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids, nil
}

// UpdatePageStatus sets the Status property on a Notion page.
// pageID must be a UUID in 8-4-4-4-12 format (36 chars).
// Idempotent: setting a page to a status it already has is a no-op from Notion's perspective.
func (c *Client) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	if len(pageID) != 36 {
		return fmt.Errorf("invalid page id length %d: %q", len(pageID), pageID)
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limiter: %w", err)
	}

	body := map[string]any{
		"properties": map[string]any{
			"Status": map[string]any{
				"status": map[string]string{
					"name": status,
				},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling page update: %w", err)
	}

	url := fmt.Sprintf("%s/v1/pages/%s", notionBaseURL, pageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating update request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("updating page %s: %w", pageID, err)
	}
	defer resp.Body.Close()               //nolint:errcheck // best-effort close on read-only HTTP response
	_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notion api returned %d for page update %s", resp.StatusCode, pageID)
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Notion-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")
}
