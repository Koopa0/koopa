// Package oreilly provides an HTTP client for the O'Reilly Learning REST API.
package oreilly

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// BaseURL is the O'Reilly Learning platform root URL.
const BaseURL = "https://learning.oreilly.com"

// maxResponseSize caps decoded response bodies to prevent unbounded reads.
const maxResponseSize = 5 << 20 // 5 MB

// SearchParams holds query parameters for the O'Reilly search API.
type SearchParams struct {
	Query      string
	Formats    []string // book, video, article, course, interactive, audiobook
	Publishers []string
	Authors    []string
	Limit      int
}

// SearchResult holds the API response.
type SearchResult struct {
	Results []Item `json:"results"`
	Next    string `json:"next"`
}

// Item is a single search result from O'Reilly.
type Item struct {
	ArchiveID     string   `json:"archive_id"`
	Title         string   `json:"title"`
	Authors       []string `json:"authors"`
	Publishers    []string `json:"publishers"`
	Issued        string   `json:"issued"`
	WebURL        string   `json:"web_url"`
	Description   string   `json:"description"`
	Popularity    int      `json:"popularity"`
	AverageRating int      `json:"average_rating"` // scaled by 1000 (e.g. 4800 = 4.8)
	Topics        []Topic  `json:"topics_payload"`
	ContentFormat string   `json:"format"`
	CoverURL      string   `json:"cover_url"`
}

// Topic is a topic tag on an O'Reilly content item.
type Topic struct {
	Slug  string  `json:"slug"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// BookDetail holds book metadata from the epubs API.
type BookDetail struct {
	Title           string `json:"title"`
	Identifier      string `json:"identifier"`
	ContentFormat   string `json:"content_format"`
	PublicationDate string `json:"publication_date"`
	PageCount       int    `json:"page_count"`
	VirtualPages    int    `json:"virtual_pages"`
	Language        string `json:"language"`
	TOCURL          string `json:"table_of_contents"`
}

// TOCEntry is a chapter entry in the table of contents.
type TOCEntry struct {
	Depth    int        `json:"depth"`
	Title    string     `json:"title"`
	Fragment string     `json:"fragment"`
	Filename string     `json:"filename"` // extracted from reference_id
	Duration float64    `json:"duration"`
	Children []TOCEntry `json:"children"`
}

// Client calls the O'Reilly Learning REST API.
type Client struct {
	token      string
	httpClient *http.Client
}

// New creates a client for the O'Reilly search API.
func New(token string) *Client {
	return &Client{
		token: token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) doGet(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.httpClient.Do(req)
}

// Search calls GET /api/v2/search/ with the given parameters.
func (c *Client) Search(ctx context.Context, p *SearchParams) (*SearchResult, error) {
	u, err := url.Parse(BaseURL + "/api/v2/search/")
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}

	q := u.Query()
	if p.Query != "" {
		q.Set("query", p.Query)
	}
	for i, f := range p.Formats {
		q.Set(fmt.Sprintf("formats[%d]", i), f)
	}
	for i, pub := range p.Publishers {
		q.Set(fmt.Sprintf("publishers[%d]", i), pub)
	}
	for i, a := range p.Authors {
		q.Set(fmt.Sprintf("authors[%d]", i), a)
	}
	q.Set("include_facets", "false")
	q.Set("highlight", "0")
	if p.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", p.Limit))
	}
	u.RawQuery = q.Encode()

	resp, err := c.doGet(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("executing search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search API returned status %d", resp.StatusCode)
	}

	var result SearchResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}
	return &result, nil
}

// BookDetail fetches book metadata and table of contents.
func (c *Client) BookDetail(ctx context.Context, archiveID string) (*BookDetail, error) {
	bookURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/", BaseURL, archiveID)

	resp, err := c.doGet(ctx, bookURL)
	if err != nil {
		return nil, fmt.Errorf("fetching book detail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("book detail API returned status %d", resp.StatusCode)
	}

	var detail BookDetail
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decoding book detail: %w", err)
	}
	return &detail, nil
}

// BookTOC fetches the table of contents for a book.
func (c *Client) BookTOC(ctx context.Context, archiveID string) ([]TOCEntry, error) {
	tocURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/table-of-contents/", BaseURL, archiveID)

	resp, err := c.doGet(ctx, tocURL)
	if err != nil {
		return nil, fmt.Errorf("fetching TOC: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TOC API returned status %d", resp.StatusCode)
	}

	// Raw TOC has reference_id like "9781835880302-/chap01.xhtml"; extract filename.
	var raw []struct {
		Depth       int     `json:"depth"`
		ReferenceID string  `json:"reference_id"`
		Title       string  `json:"title"`
		Fragment    string  `json:"fragment"`
		Duration    float64 `json:"duration"`
		Children    []struct {
			Depth    int     `json:"depth"`
			Title    string  `json:"title"`
			Fragment string  `json:"fragment"`
			Duration float64 `json:"duration"`
		} `json:"children"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding TOC: %w", err)
	}

	entries := make([]TOCEntry, 0, len(raw))
	for i := range raw {
		r := &raw[i]
		filename := ExtractFilename(r.ReferenceID)
		children := make([]TOCEntry, 0, len(r.Children))
		for j := range r.Children {
			ch := &r.Children[j]
			children = append(children, TOCEntry{
				Depth:    ch.Depth,
				Title:    ch.Title,
				Fragment: ch.Fragment,
				Duration: ch.Duration,
			})
		}
		entries = append(entries, TOCEntry{
			Depth:    r.Depth,
			Title:    r.Title,
			Fragment: r.Fragment,
			Filename: filename,
			Duration: r.Duration,
			Children: children,
		})
	}
	return entries, nil
}

// ExtractFilename pulls the filename from a reference_id like "9781835880302-/chap01.xhtml".
func ExtractFilename(refID string) string {
	if idx := strings.LastIndex(refID, "/"); idx >= 0 && idx < len(refID)-1 {
		return refID[idx+1:]
	}
	return refID
}

// ChapterContent fetches the HTML content of a chapter and strips tags to plain text.
func (c *Client) ChapterContent(ctx context.Context, archiveID, filename string) (string, error) {
	chURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/files/%s", BaseURL, archiveID, filename)

	resp, err := c.doGet(ctx, chURL)
	if err != nil {
		return "", fmt.Errorf("fetching chapter: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chapter API returned status %d", resp.StatusCode)
	}

	// Limit to 512KB to avoid huge chapters.
	const maxChapterSize = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChapterSize))
	if err != nil {
		return "", fmt.Errorf("reading chapter body: %w", err)
	}

	return StripHTML(string(body)), nil
}

// StripHTML removes HTML tags and collapses whitespace to produce readable plain text.
func StripHTML(s string) string {
	s = reHTMLTag.ReplaceAllString(s, " ")
	s = reMultiSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var (
	reHTMLTag    = regexp.MustCompile(`<[^>]*>`)
	reMultiSpace = regexp.MustCompile(`\s{2,}`)
)
