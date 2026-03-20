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
	if !validPageID(pageID) {
		return nil, fmt.Errorf("invalid page id: %q", pageID)
	}
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
	Archived   bool                       `json:"archived"`
	InTrash    bool                       `json:"in_trash"`
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
// maxPages limits the number of pagination requests to prevent unbounded growth.
const maxPages = 100 // 100 pages × 100 items = 10,000 max results

func (c *Client) QueryDataSource(ctx context.Context, dataSourceID string, filter json.RawMessage) ([]DatabaseQueryResult, error) {
	if dataSourceID == "" {
		return nil, fmt.Errorf("empty data source id")
	}
	var allResults []DatabaseQueryResult
	var cursor *string

	for range maxPages {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		body := map[string]any{
			"page_size": 100,
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

		for _, r := range qr.Results {
			if !r.Archived && !r.InTrash {
				allResults = append(allResults, r)
			}
		}

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
	if !validPageID(pageID) {
		return fmt.Errorf("invalid page id: %q", pageID)
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

// CreateTaskParams holds parameters for creating a task in the Notion Tasks database.
type CreateTaskParams struct {
	DatabaseID  string
	Title       string
	DueDate     string // YYYY-MM-DD
	Description string // optional rich text body
}

// CreateTask creates a new task page in the given Notion database.
func (c *Client) CreateTask(ctx context.Context, p CreateTaskParams) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limiter: %w", err)
	}

	properties := map[string]any{
		"Task Name": map[string]any{
			"title": []map[string]any{
				{"text": map[string]string{"content": p.Title}},
			},
		},
		"Status": map[string]any{
			"status": map[string]string{"name": "To Do"},
		},
	}
	if p.DueDate != "" {
		properties["Due"] = map[string]any{
			"date": map[string]string{"start": p.DueDate},
		}
	}

	body := map[string]any{
		"parent":     map[string]string{"data_source_id": p.DatabaseID},
		"properties": properties,
	}

	// Add description as page content block if provided
	if p.Description != "" {
		body["children"] = []map[string]any{
			{
				"object": "block",
				"type":   "paragraph",
				"paragraph": map[string]any{
					"rich_text": []map[string]any{
						{"type": "text", "text": map[string]string{"content": p.Description}},
					},
				},
			},
		}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling create task: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notionBaseURL+"/v1/pages", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating task request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("creating notion task: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notion api returned %d for create task", resp.StatusCode)
	}

	return nil
}

// DiscoveredDatabase is a Notion database returned by the Search API.
type DiscoveredDatabase struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Parent string `json:"parent"` // immediate parent page title (empty for workspace-level)
}

// SearchDatabases calls the Notion Search API to list all databases accessible by the integration.
// For each database, it fetches the immediate parent page title for disambiguation.
func (c *Client) SearchDatabases(ctx context.Context) ([]DiscoveredDatabase, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"filter": map[string]string{
			"value":    "data_source",
			"property": "object",
		},
		"page_size": 100,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling search body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notionBaseURL+"/v1/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating search request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling notion search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("notion search returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Results []struct {
			Object string `json:"object"`
			ID     string `json:"id"`
			Title  []struct {
				PlainText string `json:"plain_text"`
			} `json:"title"`
			// data_source parent is always database_id; database_parent is the page/workspace above
			DatabaseParent struct {
				Type   string `json:"type"`
				PageID string `json:"page_id"`
			} `json:"database_parent"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}

	// collect unique parent page IDs to resolve titles
	parentIDs := make(map[string]struct{})
	for _, r := range result.Results {
		if r.DatabaseParent.Type == "page_id" && r.DatabaseParent.PageID != "" {
			parentIDs[r.DatabaseParent.PageID] = struct{}{}
		}
	}

	// resolve parent page titles (best-effort, rate-limited)
	parentTitles := make(map[string]string, len(parentIDs))
	for pid := range parentIDs {
		page, pageErr := c.Page(ctx, pid)
		if pageErr != nil {
			continue // best-effort: skip unresolvable parents
		}
		// page title can be under "title" or "Name" property
		t := titleProperty(page.Properties["title"])
		if t == "" {
			t = titleProperty(page.Properties["Name"])
		}
		parentTitles[pid] = t
	}

	dbs := make([]DiscoveredDatabase, 0, len(result.Results))
	for _, r := range result.Results {
		title := r.ID
		if len(r.Title) > 0 {
			title = r.Title[0].PlainText
		}
		parent := parentTitles[r.DatabaseParent.PageID] // empty if workspace-level or unresolved
		dbs = append(dbs, DiscoveredDatabase{ID: r.ID, Title: title, Parent: parent})
	}
	return dbs, nil
}

// validPageID checks that a page ID is a 36-character UUID (8-4-4-4-12 hex).
// Prevents path traversal via crafted pageID values.
func validPageID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Notion-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")
}
