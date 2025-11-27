package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/firebase/genkit/go/ai"
	"github.com/go-shiori/go-readability"
	"github.com/gocolly/colly/v2"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/security"
)

// NetworkToolsetName is the toolset identifier constant.
const NetworkToolsetName = "network"

// Content limits.
const (
	// MaxURLsPerRequest is the maximum number of URLs allowed per web_fetch request.
	MaxURLsPerRequest = 10
	// MaxContentLength is the maximum content length per URL (50KB).
	MaxContentLength = 50000
	// MaxSearchResults is the maximum number of search results allowed.
	MaxSearchResults = 50
	// DefaultSearchResults is the default number of search results.
	DefaultSearchResults = 10
)

// NetworkToolset provides network operation tools including web search and content fetching.
//
// Tools:
//   - web_search: Search the web via SearXNG
//   - web_fetch: Fetch and extract content from URLs (HTML, JSON, text)
//
// Design principles:
//   - Capability-oriented naming (not implementation-oriented)
//   - Multi-source synthesis for unbiased information gathering
//   - Graceful degradation with partial failure support
//
// Security:
//   - SSRF protection via URL validation
//   - Blocks private IPs, cloud metadata endpoints, and localhost
type NetworkToolset struct {
	// Search configuration (SearXNG)
	searchBaseURL string
	searchClient  *http.Client

	// Fetch configuration (Colly)
	fetchParallelism int
	fetchDelay       time.Duration
	fetchTimeout     time.Duration

	// SSRF protection
	urlValidator *security.URL

	// Testing only: skip SSRF checks (NEVER use in production)
	skipSSRFCheck bool

	logger log.Logger
}

// NewNetworkToolset creates a new NetworkToolset with search and fetch capabilities.
func NewNetworkToolset(
	searchBaseURL string,
	fetchParallelism int,
	fetchDelay time.Duration,
	fetchTimeout time.Duration,
	logger log.Logger,
) (*NetworkToolset, error) {
	if searchBaseURL == "" {
		return nil, fmt.Errorf("search base URL is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if fetchParallelism <= 0 {
		fetchParallelism = 2
	}
	if fetchDelay <= 0 {
		fetchDelay = 1 * time.Second
	}
	if fetchTimeout <= 0 {
		fetchTimeout = 30 * time.Second
	}

	// Create URL validator for SSRF protection
	urlValidator := security.NewURL()

	return &NetworkToolset{
		searchBaseURL:    strings.TrimSuffix(searchBaseURL, "/"),
		searchClient:     &http.Client{Timeout: 30 * time.Second},
		fetchParallelism: fetchParallelism,
		fetchDelay:       fetchDelay,
		fetchTimeout:     fetchTimeout,
		urlValidator:     urlValidator,
		logger:           logger,
	}, nil
}

// Name returns the toolset identifier.
func (nt *NetworkToolset) Name() string {
	return NetworkToolsetName
}

// NewNetworkToolsetForTesting creates a NetworkToolset with SSRF protection disabled.
// WARNING: This is for testing ONLY. Never use in production code.
func NewNetworkToolsetForTesting(
	searchBaseURL string,
	fetchParallelism int,
	fetchDelay time.Duration,
	fetchTimeout time.Duration,
	logger log.Logger,
) (*NetworkToolset, error) {
	nt, err := NewNetworkToolset(searchBaseURL, fetchParallelism, fetchDelay, fetchTimeout, logger)
	if err != nil {
		return nil, err
	}
	nt.skipSSRFCheck = true
	return nt, nil
}

// Tools returns all network operation tools provided by this toolset.
// This is used by Genkit for tool registration.
func (nt *NetworkToolset) Tools(_ agent.ReadonlyContext) ([]Tool, error) {
	return []Tool{
		NewTool(ToolWebSearch,
			"Search the web for information. Returns relevant results with titles, URLs, and content snippets. "+
				"Use this to find current information, news, or facts from the internet.",
			true, // long running
			nt.search,
		),
		NewTool(ToolWebFetch,
			"Fetch and extract content from one or more URLs (max 10). "+
				"Supports HTML pages, JSON APIs, and plain text. "+
				"For HTML: uses Readability algorithm to extract main content. "+
				"For JSON: returns formatted JSON. "+
				"For text: returns raw content. "+
				"Supports parallel fetching with rate limiting. "+
				"Returns extracted content (max 50KB per URL). "+
				"Note: Does not render JavaScript - for SPA pages, content may be incomplete.",
			true, // long running
			nt.fetch,
		),
	}, nil
}

// Search performs web search via SearXNG.
// This is the exported method for direct invocation (e.g., from MCP handlers).
// Architecture: Consistent with FileToolset.ReadFile() and SystemToolset.ExecuteCommand().
func (nt *NetworkToolset) Search(ctx *ai.ToolContext, input SearchInput) (SearchOutput, error) {
	return nt.search(ctx, input)
}

// Fetch retrieves and extracts content from one or more URLs.
// This is the exported method for direct invocation (e.g., from MCP handlers).
// Architecture: Consistent with FileToolset.ReadFile() and SystemToolset.ExecuteCommand().
func (nt *NetworkToolset) Fetch(ctx *ai.ToolContext, input FetchInput) (FetchOutput, error) {
	return nt.fetch(ctx, input)
}

// ============================================================================
// web_search: Search the web via SearXNG
// ============================================================================

// SearchInput defines the input for web_search tool.
type SearchInput struct {
	// Query is the search query string. Required.
	Query string `json:"query" jsonschema_description:"The search query (required)"`

	// Categories filters results by type. Optional.
	Categories []string `json:"categories,omitempty" jsonschema_description:"Search categories: general, news, images, videos, science"`

	// Language specifies the preferred language. Optional.
	Language string `json:"language,omitempty" jsonschema_description:"Language code (e.g. en, zh-TW, ja)"`

	// MaxResults limits the number of results. Optional, default 10, max 50.
	MaxResults int `json:"max_results,omitempty" jsonschema_description:"Maximum results to return (default 10, max 50)"`
}

// SearchOutput defines the output for web_search tool.
type SearchOutput struct {
	Results []SearchResult `json:"results,omitempty"`
	Query   string         `json:"query"`
	Error   string         `json:"error,omitempty"` // Business error for LLM
}

// SearchResult represents a single search result.
type SearchResult struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Content     string `json:"content"`
	Engine      string `json:"engine,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
}

// search performs web search via SearXNG.
func (nt *NetworkToolset) search(ctx *ai.ToolContext, input SearchInput) (SearchOutput, error) {
	// Validate required fields
	if strings.TrimSpace(input.Query) == "" {
		return SearchOutput{}, fmt.Errorf("query is required")
	}

	nt.logger.Info("web_search called", "query", input.Query)

	// Build query URL
	u, err := url.Parse(nt.searchBaseURL + "/search")
	if err != nil {
		return SearchOutput{}, fmt.Errorf("invalid base URL: %w", err)
	}

	q := u.Query()
	q.Set("q", input.Query)
	q.Set("format", "json")

	if len(input.Categories) > 0 {
		q.Set("categories", strings.Join(input.Categories, ","))
	}
	if input.Language != "" {
		q.Set("language", input.Language)
	}
	u.RawQuery = q.Encode()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return SearchOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := nt.searchClient.Do(req)
	if err != nil {
		nt.logger.Error("search request failed", "error", err)
		return SearchOutput{}, fmt.Errorf("search request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle HTTP status codes (business errors → Error field)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return SearchOutput{Query: input.Query, Error: "Search service is rate limited. Please wait and try again."}, nil
	case resp.StatusCode >= 500:
		return SearchOutput{Query: input.Query, Error: "Search service is temporarily unavailable."}, nil
	case resp.StatusCode >= 400:
		return SearchOutput{Query: input.Query, Error: fmt.Sprintf("Search request error: HTTP %d", resp.StatusCode)}, nil
	}

	// Parse response
	var searxResp searxngResponse
	if err := json.NewDecoder(resp.Body).Decode(&searxResp); err != nil {
		return SearchOutput{}, fmt.Errorf("parse response: %w", err)
	}

	// Apply result limit
	maxResults := input.MaxResults
	if maxResults <= 0 {
		maxResults = DefaultSearchResults
	}
	if maxResults > MaxSearchResults {
		maxResults = MaxSearchResults
	}

	// Convert to output format
	results := make([]SearchResult, 0, min(len(searxResp.Results), maxResults))
	for i, r := range searxResp.Results {
		if i >= maxResults {
			break
		}
		results = append(results, SearchResult{
			Title:       r.Title,
			URL:         r.URL,
			Content:     r.Content,
			Engine:      r.Engine,
			PublishedAt: r.PublishedDate,
		})
	}

	if len(results) == 0 {
		return SearchOutput{Query: input.Query, Error: "No results found for this query."}, nil
	}

	nt.logger.Info("web_search completed", "query", input.Query, "results", len(results))
	return SearchOutput{Results: results, Query: input.Query}, nil
}

// searxngResponse is the internal response structure from SearXNG API.
type searxngResponse struct {
	Results []struct {
		Title         string `json:"title"`
		URL           string `json:"url"`
		Content       string `json:"content"`
		Engine        string `json:"engine"`
		PublishedDate string `json:"publishedDate"`
	} `json:"results"`
}

// ============================================================================
// web_fetch: Fetch and extract content from URLs
// ============================================================================

// FetchInput defines the input for web_fetch tool.
type FetchInput struct {
	// URLs is one or more URLs to fetch. Required, max 10.
	URLs []string `json:"urls" jsonschema_description:"One or more URLs to fetch (required, max 10)"`

	// Selector is an optional CSS selector to extract specific content.
	// If empty, attempts to extract main content automatically using Readability.
	Selector string `json:"selector,omitempty" jsonschema_description:"CSS selector to extract specific content (e.g. 'article', 'main', '.content')"`
}

// FetchOutput defines the output for web_fetch tool.
type FetchOutput struct {
	// Results contains the fetched content for each URL.
	Results []FetchResult `json:"results"`

	// FailedURLs lists URLs that failed to fetch with reasons.
	FailedURLs []FailedURL `json:"failed_urls,omitempty"`
}

// FetchResult represents successfully fetched content from a single URL.
type FetchResult struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"` // e.g., "text/html", "application/json", "text/plain"
}

// FailedURL represents a URL that failed to fetch.
type FailedURL struct {
	URL        string `json:"url"`
	Reason     string `json:"reason"`
	StatusCode int    `json:"status_code,omitempty"` // HTTP status code if available
}

// fetch retrieves and extracts content from one or more URLs.
// Includes SSRF protection to block private IPs and cloud metadata endpoints.
func (nt *NetworkToolset) fetch(ctx *ai.ToolContext, input FetchInput) (FetchOutput, error) {
	// Validate input
	if len(input.URLs) == 0 {
		return FetchOutput{}, fmt.Errorf("at least one URL is required")
	}
	if len(input.URLs) > MaxURLsPerRequest {
		return FetchOutput{}, fmt.Errorf("maximum %d URLs allowed per request", MaxURLsPerRequest)
	}

	// SSRF protection - validate and filter URLs before fetching
	var failedURLs []FailedURL
	var safeURLs []string

	urlSet := make(map[string]struct{}) // For deduplication
	for _, u := range input.URLs {
		// Skip duplicates
		if _, exists := urlSet[u]; exists {
			continue
		}
		urlSet[u] = struct{}{}

		// Validate URL for SSRF (skip in testing mode)
		if !nt.skipSSRFCheck {
			if err := nt.urlValidator.Validate(u); err != nil {
				nt.logger.Warn("SSRF blocked", "url", u, "reason", err)
				failedURLs = append(failedURLs, FailedURL{
					URL:    u,
					Reason: fmt.Sprintf("blocked: %v", err),
				})
				continue
			}
		}
		safeURLs = append(safeURLs, u)
	}

	// If all URLs were blocked, return early
	if len(safeURLs) == 0 {
		nt.logger.Warn("web_fetch: all URLs blocked by SSRF protection", "blocked", len(failedURLs))
		return FetchOutput{FailedURLs: failedURLs}, nil
	}

	nt.logger.Info("web_fetch called", "urls", len(safeURLs), "blocked", len(failedURLs))

	// Create Colly collector for this request
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(1), // Don't follow links
		colly.UserAgent("Mozilla/5.0 (compatible; KoopaBot/1.0; +https://github.com/koopa0/koopa)"),
	)

	// SSRF protection in redirect handler
	// Validate redirect targets to prevent SSRF via redirects
	c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("stopped after 5 redirects")
		}
		// Check redirect target for SSRF (skip in testing mode)
		if !nt.skipSSRFCheck {
			if err := nt.urlValidator.Validate(req.URL.String()); err != nil {
				nt.logger.Warn("SSRF blocked redirect", "url", req.URL.String(), "reason", err)
				return fmt.Errorf("redirect blocked: %w", err)
			}
		}
		return nil
	})

	// Set timeout
	c.SetRequestTimeout(nt.fetchTimeout)

	// Rate limiting per domain
	if err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: nt.fetchParallelism,
		Delay:       nt.fetchDelay,
	}); err != nil {
		return FetchOutput{}, fmt.Errorf("set rate limit: %w", err)
	}

	// Results collection (thread-safe)
	// Note: failedURLs already contains SSRF-blocked URLs from earlier
	var (
		mu      sync.Mutex
		results []FetchResult
	)

	// Track which URLs have been processed (to avoid double processing)
	processedURLs := make(map[string]struct{})
	var processedMu sync.Mutex

	// Context cancellation check
	c.OnRequest(func(r *colly.Request) {
		select {
		case <-ctx.Done():
			r.Abort()
		default:
		}
	})

	// Determine content selector (used as fallback for HTML)
	selector := input.Selector
	if selector == "" {
		selector = "article, main, [role=main], .post-content, .article-content, .entry-content, .content"
	}

	// OnResponse handles non-HTML content (JSON, Text, XML)
	c.OnResponse(func(r *colly.Response) {
		contentType := r.Headers.Get("Content-Type")
		urlStr := r.Request.URL.String()

		// Skip HTML - will be handled by OnHTML
		if strings.Contains(contentType, "text/html") {
			return
		}

		processedMu.Lock()
		if _, exists := processedURLs[urlStr]; exists {
			processedMu.Unlock()
			return
		}
		processedURLs[urlStr] = struct{}{}
		processedMu.Unlock()

		var content string
		var title string

		switch {
		case strings.Contains(contentType, "application/json"):
			// Pretty-print JSON for better LLM readability
			var jsonData any
			if err := json.Unmarshal(r.Body, &jsonData); err == nil {
				if pretty, err := json.MarshalIndent(jsonData, "", "  "); err == nil {
					content = string(pretty)
				} else {
					content = string(r.Body)
				}
			} else {
				content = string(r.Body)
			}
			title = "JSON Response"

		case strings.Contains(contentType, "text/plain"),
			strings.Contains(contentType, "text/xml"),
			strings.Contains(contentType, "application/xml"):
			content = string(r.Body)
			title = "Text Content"

		default:
			// Unknown content type - try to use as text
			content = string(r.Body)
			title = "Content"
		}

		// Truncate if too long
		if len(content) > MaxContentLength {
			content = content[:MaxContentLength] + "\n\n[Content truncated...]"
		}

		mu.Lock()
		results = append(results, FetchResult{
			URL:         urlStr,
			Title:       title,
			Content:     strings.TrimSpace(content),
			ContentType: contentType,
		})
		mu.Unlock()
	})

	// OnHTML handles HTML content with go-readability
	c.OnHTML("html", func(e *colly.HTMLElement) {
		urlStr := e.Request.URL.String()

		processedMu.Lock()
		if _, exists := processedURLs[urlStr]; exists {
			processedMu.Unlock()
			return
		}
		processedURLs[urlStr] = struct{}{}
		processedMu.Unlock()

		// Use Response.Body for full HTML (more reliable than DOM.Html())
		htmlBytes := e.Response.Body
		if len(htmlBytes) == 0 {
			nt.logger.Warn("empty response body", "url", urlStr)
			return
		}

		// Use go-readability for content extraction
		// Pass e.Request.URL directly - it's already parsed and reflects final URL after redirects
		title, content := nt.extractWithReadability(e.Request.URL, string(htmlBytes), e, selector)

		// Truncate if too long
		if len(content) > MaxContentLength {
			content = content[:MaxContentLength] + "\n\n[Content truncated...]"
		}

		mu.Lock()
		results = append(results, FetchResult{
			URL:         urlStr,
			Title:       strings.TrimSpace(title),
			Content:     strings.TrimSpace(content),
			ContentType: "text/html",
		})
		mu.Unlock()
	})

	// On error
	c.OnError(func(r *colly.Response, err error) {
		reason := err.Error()
		statusCode := 0
		if r.StatusCode > 0 {
			statusCode = r.StatusCode
			reason = fmt.Sprintf("HTTP %d: %s", r.StatusCode, reason)
		}

		mu.Lock()
		failedURLs = append(failedURLs, FailedURL{
			URL:        r.Request.URL.String(),
			Reason:     reason,
			StatusCode: statusCode,
		})
		mu.Unlock()

		nt.logger.Warn("fetch failed", "url", r.Request.URL.String(), "status", statusCode, "error", err)
	})

	// Visit all safe URLs (already SSRF-validated)
	for _, u := range safeURLs {
		if err := c.Visit(u); err != nil {
			mu.Lock()
			failedURLs = append(failedURLs, FailedURL{
				URL:    u,
				Reason: err.Error(),
			})
			mu.Unlock()
		}
	}

	// Wait for all requests to complete
	c.Wait()

	nt.logger.Info("web_fetch completed",
		"success", len(results),
		"failed", len(failedURLs))

	return FetchOutput{
		Results:    results,
		FailedURLs: failedURLs,
	}, nil
}

// extractWithReadability extracts content using go-readability with CSS selector fallback.
// Returns (title, content).
// u should be the final URL after redirects (e.Request.URL from Colly).
func (nt *NetworkToolset) extractWithReadability(u *url.URL, html string, e *colly.HTMLElement, selector string) (string, string) {
	// Try go-readability first (Mozilla Readability algorithm)
	// u is already parsed and reflects the final URL after any redirects
	article, err := readability.FromReader(bytes.NewReader([]byte(html)), u)
	if err == nil && article.Content != "" {
		// Readability succeeded - return extracted content
		title := article.Title
		if title == "" {
			title = e.ChildText("title")
		}

		// Convert HTML content to plain text (remove tags)
		content := nt.htmlToText(article.Content)
		if content != "" {
			return title, content
		}
	}

	// Readability failed or returned empty - fallback to CSS selector
	nt.logger.Debug("readability fallback to selector", "url", u.String())
	return nt.extractWithSelector(e, selector)
}

// extractWithSelector extracts content using CSS selectors (fallback method).
// Returns (title, content).
func (nt *NetworkToolset) extractWithSelector(e *colly.HTMLElement, selector string) (string, string) {
	// Extract title
	title := e.ChildText("title")
	if title == "" {
		title = e.ChildText("h1")
	}

	// Try each selector in order
	selectors := strings.Split(selector, ",")
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if content := e.ChildText(sel); content != "" {
			return title, content
		}
	}

	// Fallback: extract from body, excluding script/style/nav/footer
	var contentParts []string
	e.ForEach("body p, body h1, body h2, body h3, body h4, body h5, body h6, body li", func(_ int, el *colly.HTMLElement) {
		if text := strings.TrimSpace(el.Text); text != "" {
			contentParts = append(contentParts, text)
		}
	})

	return title, strings.Join(contentParts, "\n\n")
}

// htmlToText converts HTML content to plain text.
func (nt *NetworkToolset) htmlToText(html string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return ""
	}

	// Remove script and style elements
	doc.Find("script, style, noscript").Remove()

	// Get text content
	return strings.TrimSpace(doc.Text())
}
