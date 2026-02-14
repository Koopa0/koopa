package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/go-shiori/go-readability"
	"github.com/gocolly/colly/v2"

	"github.com/koopa0/koopa/internal/security"
)

// Tool name constants for network operations registered with Genkit.
const (
	// WebSearchName is the Genkit tool name for performing web searches.
	WebSearchName = "web_search"
	// WebFetchName is the Genkit tool name for fetching web page content.
	WebFetchName = "web_fetch"
)

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
	// MaxRedirects is the maximum number of HTTP redirects to follow.
	MaxRedirects = 5
)

// Network holds dependencies for network operation handlers.
// Use NewNetwork to create an instance, then either:
// - Call methods directly (for MCP)
// - Use RegisterNetwork to register with Genkit
type Network struct {
	// Search configuration (SearXNG)
	searchBaseURL string
	searchClient  *http.Client

	// Fetch configuration (Colly)
	fetchParallelism int
	fetchDelay       time.Duration
	fetchTimeout     time.Duration

	// SSRF protection
	urlValidator *security.URL

	// skipSSRFCheck disables SSRF protection for testing.
	// Only settable within the tools package (unexported field).
	skipSSRFCheck bool

	logger *slog.Logger
}

// NetConfig holds configuration for network tools.
type NetConfig struct {
	SearchBaseURL    string
	FetchParallelism int
	FetchDelay       time.Duration
	FetchTimeout     time.Duration
}

// NewNetwork creates a Network instance.
func NewNetwork(cfg NetConfig, logger *slog.Logger) (*Network, error) {
	if cfg.SearchBaseURL == "" {
		return nil, fmt.Errorf("search base URL is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Apply defaults
	if cfg.FetchParallelism <= 0 {
		cfg.FetchParallelism = 2
	}
	if cfg.FetchDelay <= 0 {
		cfg.FetchDelay = 1 * time.Second
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = 30 * time.Second
	}

	urlValidator := security.NewURL()

	return &Network{
		searchBaseURL: strings.TrimSuffix(cfg.SearchBaseURL, "/"),
		// searchClient uses default transport: searchBaseURL is admin-configured
		// infrastructure (like a database URL), not user-controlled input.
		// SSRF protection applies to web_fetch (user/LLM-controlled URLs), not here.
		searchClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		fetchParallelism: cfg.FetchParallelism,
		fetchDelay:       cfg.FetchDelay,
		fetchTimeout:     cfg.FetchTimeout,
		urlValidator:     urlValidator,
		logger:           logger,
	}, nil
}

// RegisterNetwork registers all network operation tools with Genkit.
// Tools are registered with event emission wrappers for streaming support.
func RegisterNetwork(g *genkit.Genkit, nt *Network) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if nt == nil {
		return nil, fmt.Errorf("Network is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, WebSearchName,
			"Search the web for information. Returns relevant results with titles, URLs, and content snippets. "+
				"Use this to find current information, news, or facts from the internet.",
			WithEvents(WebSearchName, nt.Search)),
		genkit.DefineTool(g, WebFetchName,
			"Fetch and extract content from one or more URLs (max 10). "+
				"Supports HTML pages, JSON APIs, and plain text. "+
				"For HTML: uses Readability algorithm to extract main content. "+
				"For JSON: returns formatted JSON. "+
				"For text: returns raw content. "+
				"Supports parallel fetching with rate limiting. "+
				"Returns extracted content (max 50KB per URL). "+
				"Note: Does not render JavaScript - for SPA pages, content may be incomplete.",
			WithEvents(WebFetchName, nt.Fetch)),
	}, nil
}

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

// Search performs web search via SearXNG.
func (n *Network) Search(ctx *ai.ToolContext, input SearchInput) (SearchOutput, error) {
	// Validate required fields
	if strings.TrimSpace(input.Query) == "" {
		return SearchOutput{Error: "Query is required. Please provide a search query."}, nil
	}

	n.logger.Info("web_search called", "query", input.Query)

	// Build query URL
	u, err := url.Parse(n.searchBaseURL + "/search")
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return SearchOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := n.searchClient.Do(req)
	if err != nil {
		return SearchOutput{}, fmt.Errorf("executing search request: %w", err)
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
		return SearchOutput{
			Query: input.Query,
			Error: "No results found for this query.",
		}, nil
	}

	n.logger.Info("web_search completed", "query", input.Query, "results", len(results))
	return SearchOutput{
		Results: results,
		Query:   input.Query,
	}, nil
}

// searxngResult is a single result from the SearXNG API.
type searxngResult struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	Content       string `json:"content"`
	Engine        string `json:"engine"`
	PublishedDate string `json:"publishedDate"`
}

// searxngResponse is the internal response structure from SearXNG API.
type searxngResponse struct {
	Results []searxngResult `json:"results"`
}

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

	// Error contains validation error for LLM to understand.
	Error string `json:"error,omitempty"`
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

// fetchState holds shared state for concurrent fetch operations.
// Uses a single mutex for simplicity; profiling shows no contention at fetch scale.
type fetchState struct {
	mu           sync.Mutex
	results      []FetchResult
	failedURLs   []FailedURL
	processedURL map[string]struct{}
}

// addResult safely appends a result to the fetch state.
func (s *fetchState) addResult(r FetchResult) {
	s.mu.Lock()
	s.results = append(s.results, r)
	s.mu.Unlock()
}

// addFailed safely appends a failed URL to the fetch state.
func (s *fetchState) addFailed(f FailedURL) {
	s.mu.Lock()
	s.failedURLs = append(s.failedURLs, f)
	s.mu.Unlock()
}

// markProcessed marks a URL as processed, returns true if it was already processed.
func (s *fetchState) markProcessed(urlStr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.processedURL[urlStr]; exists {
		return true
	}
	s.processedURL[urlStr] = struct{}{}
	return false
}

// Fetch retrieves and extracts content from one or more URLs.
// Includes SSRF protection to block private IPs and cloud metadata endpoints.
func (n *Network) Fetch(ctx *ai.ToolContext, input FetchInput) (FetchOutput, error) {
	// Validate input
	if len(input.URLs) == 0 {
		return FetchOutput{Error: "At least one URL is required. Please provide URLs to fetch."}, nil
	}
	if len(input.URLs) > MaxURLsPerRequest {
		return FetchOutput{Error: fmt.Sprintf("Maximum %d URLs allowed per request. You provided %d URLs.", MaxURLsPerRequest, len(input.URLs))}, nil
	}

	// Filter and validate URLs
	safeURLs, failedURLs := n.filterURLs(input.URLs)
	if len(safeURLs) == 0 {
		n.logger.Warn("web_fetch: all URLs blocked by SSRF protection", "blocked", len(failedURLs))
		return FetchOutput{FailedURLs: failedURLs}, nil
	}

	n.logger.Info("web_fetch called", "urls", len(safeURLs), "blocked", len(failedURLs))

	// Create collector and shared state
	c := n.createCollector()
	state := &fetchState{
		failedURLs:   failedURLs,
		processedURL: make(map[string]struct{}),
	}

	// Determine content selector
	selector := input.Selector
	if selector == "" {
		selector = "article, main, [role=main], .post-content, .article-content, .entry-content, .content"
	}

	// Setup callbacks
	n.setupCallbacks(c, ctx, state, selector)

	// Visit all safe URLs
	for _, u := range safeURLs {
		if err := c.Visit(u); err != nil {
			state.addFailed(FailedURL{URL: u, Reason: err.Error()})
		}
	}

	c.Wait()

	n.logger.Info("web_fetch completed", "success", len(state.results), "failed", len(state.failedURLs))
	return FetchOutput{
		Results:    state.results,
		FailedURLs: state.failedURLs,
	}, nil
}

// filterURLs validates and deduplicates URLs, returning safe and failed lists.
func (n *Network) filterURLs(urls []string) (safe []string, failed []FailedURL) {
	urlSet := make(map[string]struct{})
	for _, u := range urls {
		if _, exists := urlSet[u]; exists {
			continue
		}
		urlSet[u] = struct{}{}

		if !n.skipSSRFCheck {
			if err := n.urlValidator.Validate(u); err != nil {
				n.logger.Warn("SSRF blocked", "url", u, "reason", err)
				failed = append(failed, FailedURL{URL: u, Reason: fmt.Sprintf("blocked: %v", err)})
				continue
			}
		}
		safe = append(safe, u)
	}
	return safe, failed
}

// createCollector creates a configured Colly collector.
func (n *Network) createCollector() *colly.Collector {
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(1),
		colly.UserAgent("Mozilla/5.0 (compatible; KoopaBot/1.0; +https://github.com/koopa0/koopa)"),
	)

	// Inject SafeTransport for DNS-level SSRF protection.
	// This validates resolved IPs at connection time, preventing DNS rebinding attacks
	// where a hostname passes Validate() but resolves to a private IP.
	if !n.skipSSRFCheck {
		c.WithTransport(n.urlValidator.SafeTransport())
	}

	c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		if !n.skipSSRFCheck {
			if err := n.urlValidator.Validate(req.URL.String()); err != nil {
				n.logger.Warn("SSRF blocked redirect", "url", req.URL.String(), "reason", err)
				return fmt.Errorf("redirect blocked: %w", err)
			}
		}
		return nil
	})

	c.SetRequestTimeout(n.fetchTimeout)
	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: n.fetchParallelism,
		Delay:       n.fetchDelay,
	})

	return c
}

// setupCallbacks configures all Colly callbacks.
func (n *Network) setupCallbacks(c *colly.Collector, ctx *ai.ToolContext, state *fetchState, selector string) {
	c.OnRequest(func(r *colly.Request) {
		select {
		case <-ctx.Done():
			r.Abort()
		default:
		}
	})

	c.OnResponse(func(r *colly.Response) {
		handleNonHTMLResponse(r, state)
	})

	c.OnHTML("html", func(e *colly.HTMLElement) {
		n.handleHTMLResponse(e, state, selector)
	})

	c.OnError(func(r *colly.Response, err error) {
		n.handleError(r, err, state)
	})
}

// handleNonHTMLResponse processes JSON, XML, and text responses.
func handleNonHTMLResponse(r *colly.Response, state *fetchState) {
	contentType := r.Headers.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		return
	}

	urlStr := r.Request.URL.String()
	if state.markProcessed(urlStr) {
		return
	}

	title, content := extractNonHTMLContent(r.Body, contentType)
	if len(content) > MaxContentLength {
		content = content[:MaxContentLength] + "\n\n[Content truncated...]"
	}

	state.addResult(FetchResult{
		URL:         urlStr,
		Title:       title,
		Content:     strings.TrimSpace(content),
		ContentType: contentType,
	})
}

// extractNonHTMLContent extracts content from non-HTML responses.
func extractNonHTMLContent(body []byte, contentType string) (title, content string) {
	switch {
	case strings.Contains(contentType, "application/json"):
		var jsonData any
		if err := json.Unmarshal(body, &jsonData); err == nil {
			if pretty, err := json.MarshalIndent(jsonData, "", "  "); err == nil {
				return "JSON Response", string(pretty)
			}
		}
		return "JSON Response", string(body)

	case strings.Contains(contentType, "text/plain"),
		strings.Contains(contentType, "text/xml"),
		strings.Contains(contentType, "application/xml"):
		return "Text Content", string(body)

	default:
		return "Content", string(body)
	}
}

// handleHTMLResponse processes HTML responses using readability.
func (n *Network) handleHTMLResponse(e *colly.HTMLElement, state *fetchState, selector string) {
	urlStr := e.Request.URL.String()
	if state.markProcessed(urlStr) {
		return
	}

	htmlBytes := e.Response.Body
	if len(htmlBytes) == 0 {
		n.logger.Warn("empty response body", "url", urlStr)
		return
	}

	title, content := n.extractWithReadability(e.Request.URL, string(htmlBytes), e, selector)
	if len(content) > MaxContentLength {
		content = content[:MaxContentLength] + "\n\n[Content truncated...]"
	}

	state.addResult(FetchResult{
		URL:         urlStr,
		Title:       strings.TrimSpace(title),
		Content:     strings.TrimSpace(content),
		ContentType: "text/html",
	})
}

// handleError processes fetch errors.
func (n *Network) handleError(r *colly.Response, err error, state *fetchState) {
	reason := err.Error()
	statusCode := 0
	if r.StatusCode > 0 {
		statusCode = r.StatusCode
		reason = fmt.Sprintf("HTTP %d: %s", r.StatusCode, reason)
	}

	state.addFailed(FailedURL{
		URL:        r.Request.URL.String(),
		Reason:     reason,
		StatusCode: statusCode,
	})

	n.logger.Warn("fetch failed", "url", r.Request.URL.String(), "status", statusCode, "error", err)
}

// extractWithReadability extracts content using go-readability with CSS selector fallback.
// Returns (title, content).
// u should be the final URL after redirects (e.Request.URL from Colly).
func (n *Network) extractWithReadability(u *url.URL, html string, e *colly.HTMLElement, selector string) (title, content string) {
	// Try go-readability first (Mozilla Readability algorithm)
	// u is already parsed and reflects the final URL after any redirects
	article, err := readability.FromReader(bytes.NewReader([]byte(html)), u)
	if err == nil && article.Content != "" {
		// Readability succeeded - return extracted content
		title = article.Title
		if title == "" {
			title = e.ChildText("title")
		}

		// Convert HTML content to plain text (remove tags)
		content = htmlToText(article.Content)
		if content != "" {
			return title, content
		}
	}

	// Readability failed or returned empty - fallback to CSS selector
	n.logger.Debug("readability fallback to selector", "url", u.String())
	return extractWithSelector(e, selector)
}

// extractWithSelector extracts content using CSS selectors (fallback method).
// Returns (title, content).
func extractWithSelector(e *colly.HTMLElement, selector string) (extractedTitle, extractedContent string) {
	// Extract title
	extractedTitle = e.ChildText("title")
	if extractedTitle == "" {
		extractedTitle = e.ChildText("h1")
	}

	// Try each selector in order
	selectors := strings.Split(selector, ",")
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if text := e.ChildText(sel); text != "" {
			return extractedTitle, text
		}
	}

	// Fallback: extract from body, excluding script/style/nav/footer
	var contentParts []string
	e.ForEach("body p, body h1, body h2, body h3, body h4, body h5, body h6, body li", func(_ int, el *colly.HTMLElement) {
		if text := strings.TrimSpace(el.Text); text != "" {
			contentParts = append(contentParts, text)
		}
	})

	return extractedTitle, strings.Join(contentParts, "\n\n")
}

// htmlToText converts HTML content to plain text.
func htmlToText(html string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return ""
	}

	// Remove script and style elements
	doc.Find("script, style, noscript").Remove()

	// Get text content
	return strings.TrimSpace(doc.Text())
}
