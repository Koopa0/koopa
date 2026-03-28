package mcp

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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// OReillySearchParams holds query parameters for the O'Reilly search API.
type OReillySearchParams struct {
	Query      string
	Formats    []string // book, video, article, course, interactive, audiobook
	Publishers []string
	Authors    []string
	Limit      int
}

// OReillySearchResult holds the API response.
type OReillySearchResult struct {
	Results []OReillyItem `json:"results"`
	Next    string        `json:"next"`
}

// OReillyItem is a single search result from O'Reilly.
type OReillyItem struct {
	ArchiveID     string         `json:"archive_id"`
	Title         string         `json:"title"`
	Authors       []string       `json:"authors"`
	Publishers    []string       `json:"publishers"`
	Issued        string         `json:"issued"`
	WebURL        string         `json:"web_url"`
	Description   string         `json:"description"`
	Popularity    int            `json:"popularity"`
	AverageRating int            `json:"average_rating"` // scaled by 1000 (e.g. 4800 = 4.8)
	Topics        []oreillyTopic `json:"topics_payload"`
	ContentFormat string         `json:"format"`
	CoverURL      string         `json:"cover_url"`
}

type oreillyTopic struct {
	Slug  string  `json:"slug"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// OReillyBookDetail holds book metadata from the epubs API.
type OReillyBookDetail struct {
	Title           string `json:"title"`
	Identifier      string `json:"identifier"`
	ContentFormat   string `json:"content_format"`
	PublicationDate string `json:"publication_date"`
	PageCount       int    `json:"page_count"`
	VirtualPages    int    `json:"virtual_pages"`
	Language        string `json:"language"`
	TOCURL          string `json:"table_of_contents"`
}

// OReillyTOCEntry is a chapter entry in the table of contents.
type OReillyTOCEntry struct {
	Depth    int               `json:"depth"`
	Title    string            `json:"title"`
	Fragment string            `json:"fragment"`
	Filename string            `json:"filename"` // extracted from reference_id
	Duration float64           `json:"duration"`
	Children []OReillyTOCEntry `json:"children"`
}

// OReillyClient calls the O'Reilly Learning REST API.
type OReillyClient struct {
	token      string
	httpClient *http.Client
}

const (
	oreillyBaseURL         = "https://learning.oreilly.com"
	maxOReillyResponseSize = 5 << 20 // 5 MB
)

// NewOReillyClient creates a client for the O'Reilly search API.
func NewOReillyClient(token string) *OReillyClient {
	return &OReillyClient{
		token: token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *OReillyClient) doGet(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.httpClient.Do(req)
}

// Search calls GET /api/v2/search/ with the given parameters.
func (c *OReillyClient) Search(ctx context.Context, p *OReillySearchParams) (*OReillySearchResult, error) {
	u, err := url.Parse(oreillyBaseURL + "/api/v2/search/")
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

	var result OReillySearchResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOReillyResponseSize)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}
	return &result, nil
}

// BookDetail fetches book metadata and table of contents.
func (c *OReillyClient) BookDetail(ctx context.Context, archiveID string) (*OReillyBookDetail, error) {
	bookURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/", oreillyBaseURL, archiveID)

	resp, err := c.doGet(ctx, bookURL)
	if err != nil {
		return nil, fmt.Errorf("fetching book detail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("book detail API returned status %d", resp.StatusCode)
	}

	var detail OReillyBookDetail
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOReillyResponseSize)).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decoding book detail: %w", err)
	}
	return &detail, nil
}

// BookTOC fetches the table of contents for a book.
func (c *OReillyClient) BookTOC(ctx context.Context, archiveID string) ([]OReillyTOCEntry, error) {
	tocURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/table-of-contents/", oreillyBaseURL, archiveID)

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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOReillyResponseSize)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding TOC: %w", err)
	}

	entries := make([]OReillyTOCEntry, 0, len(raw))
	for i := range raw {
		r := &raw[i]
		filename := extractFilename(r.ReferenceID)
		children := make([]OReillyTOCEntry, 0, len(r.Children))
		for j := range r.Children {
			ch := &r.Children[j]
			children = append(children, OReillyTOCEntry{
				Depth:    ch.Depth,
				Title:    ch.Title,
				Fragment: ch.Fragment,
				Duration: ch.Duration,
			})
		}
		entries = append(entries, OReillyTOCEntry{
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

// extractFilename pulls the filename from a reference_id like "9781835880302-/chap01.xhtml".
func extractFilename(refID string) string {
	if idx := strings.LastIndex(refID, "/"); idx >= 0 && idx < len(refID)-1 {
		return refID[idx+1:]
	}
	return refID
}

// ChapterContent fetches the HTML content of a chapter and strips tags to plain text.
func (c *OReillyClient) ChapterContent(ctx context.Context, archiveID, filename string) (string, error) {
	chURL := fmt.Sprintf("%s/api/v2/epubs/urn:orm:book:%s/files/%s", oreillyBaseURL, archiveID, filename)

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

	return stripHTML(string(body)), nil
}

// stripHTML removes HTML tags and collapses whitespace to produce readable plain text.
func stripHTML(s string) string {
	s = reHTMLTag.ReplaceAllString(s, " ")
	s = reMultiSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var (
	reHTMLTag    = regexp.MustCompile(`<[^>]*>`)
	reMultiSpace = regexp.MustCompile(`\s{2,}`)
)

// --- MCP tools ---

// SearchOReillyInput is the input schema for the search_oreilly_content tool.
type SearchOReillyInput struct {
	Query      string   `json:"query" jsonschema_description:"search query (e.g. 'kubernetes', 'Go concurrency')"`
	Formats    []string `json:"formats,omitempty" jsonschema_description:"content formats: book, video, article, course, interactive, audiobook"`
	Publishers []string `json:"publishers,omitempty" jsonschema_description:"filter by publisher (e.g. 'O'Reilly Media, Inc.')"`
	Authors    []string `json:"authors,omitempty" jsonschema_description:"filter by author name"`
	Limit      int      `json:"limit,omitempty" jsonschema_description:"max results (default 10, max 50)"`
}

// SearchOReillyOutput is the output of the search_oreilly_content tool.
type SearchOReillyOutput struct {
	Results []oreillyResult `json:"results"`
	Total   int             `json:"total"`
}

type oreillyResult struct {
	ArchiveID     string   `json:"archive_id"`
	Title         string   `json:"title"`
	Authors       []string `json:"authors"`
	Format        string   `json:"format,omitempty"`
	Issued        string   `json:"issued,omitempty"`
	URL           string   `json:"url"`
	CoverURL      string   `json:"cover_url,omitempty"`
	Description   string   `json:"description,omitempty"`
	AverageRating float64  `json:"average_rating,omitempty"`
	Topics        []string `json:"topics,omitempty"`
}

func (s *Server) searchOReillyContent(ctx context.Context, _ *mcp.CallToolRequest, input *SearchOReillyInput) (*mcp.CallToolResult, SearchOReillyOutput, error) {
	if s.oreilly == nil {
		return nil, SearchOReillyOutput{}, fmt.Errorf("O'Reilly search is not configured (ORM_JWT not set)")
	}
	if input.Query == "" {
		return nil, SearchOReillyOutput{}, fmt.Errorf("query is required")
	}
	if len(input.Query) > maxQueryLen {
		return nil, SearchOReillyOutput{}, fmt.Errorf("query too long (max %d characters)", maxQueryLen)
	}

	limit := clamp(input.Limit, 1, 50, 10)

	result, err := s.oreilly.Search(ctx, &OReillySearchParams{
		Query:      input.Query,
		Formats:    input.Formats,
		Publishers: input.Publishers,
		Authors:    input.Authors,
		Limit:      limit,
	})
	if err != nil {
		return nil, SearchOReillyOutput{}, fmt.Errorf("searching O'Reilly: %w", err)
	}

	out := SearchOReillyOutput{
		Total: len(result.Results),
	}
	for i := range result.Results {
		item := &result.Results[i]
		topics := make([]string, 0, len(item.Topics))
		for _, t := range item.Topics {
			topics = append(topics, t.Name)
		}

		desc := item.Description
		if len(desc) > 300 {
			desc = desc[:300] + "..."
		}

		out.Results = append(out.Results, oreillyResult{
			ArchiveID:     item.ArchiveID,
			Title:         item.Title,
			Authors:       item.Authors,
			Format:        item.ContentFormat,
			Issued:        item.Issued,
			URL:           oreillyBaseURL + item.WebURL,
			CoverURL:      item.CoverURL,
			Description:   desc,
			AverageRating: float64(item.AverageRating) / 1000.0,
			Topics:        topics,
		})
	}
	return nil, out, nil
}

// --- get_oreilly_book_detail ---

// BookDetailInput is the input for the get_oreilly_book_detail tool.
type BookDetailInput struct {
	ArchiveID string `json:"archive_id" jsonschema_description:"book identifier from search results (e.g. '9781835880302')"`
}

// BookDetailOutput is the output of the get_oreilly_book_detail tool.
type BookDetailOutput struct {
	Title           string           `json:"title"`
	Identifier      string           `json:"identifier"`
	Format          string           `json:"format"`
	PublicationDate string           `json:"publication_date"`
	PageCount       int              `json:"page_count"`
	Language        string           `json:"language"`
	URL             string           `json:"url"`
	Chapters        []chapterSummary `json:"chapters"`
}

type chapterSummary struct {
	Title    string           `json:"title"`
	Filename string           `json:"filename"`
	Minutes  float64          `json:"minutes,omitempty"`
	Sections []sectionSummary `json:"sections,omitempty"`
}

type sectionSummary struct {
	Title string `json:"title"`
}

func (s *Server) getOReillyBookDetail(ctx context.Context, _ *mcp.CallToolRequest, input *BookDetailInput) (*mcp.CallToolResult, BookDetailOutput, error) {
	if s.oreilly == nil {
		return nil, BookDetailOutput{}, fmt.Errorf("O'Reilly search is not configured (ORM_JWT not set)")
	}
	if input.ArchiveID == "" {
		return nil, BookDetailOutput{}, fmt.Errorf("archive_id is required")
	}

	detail, err := s.oreilly.BookDetail(ctx, input.ArchiveID)
	if err != nil {
		return nil, BookDetailOutput{}, fmt.Errorf("fetching book detail: %w", err)
	}

	toc, err := s.oreilly.BookTOC(ctx, input.ArchiveID)
	if err != nil {
		return nil, BookDetailOutput{}, fmt.Errorf("fetching table of contents: %w", err)
	}

	chapters := make([]chapterSummary, 0, len(toc))
	for i := range toc {
		entry := &toc[i]
		sections := make([]sectionSummary, 0, len(entry.Children))
		for j := range entry.Children {
			sections = append(sections, sectionSummary{
				Title: entry.Children[j].Title,
			})
		}
		chapters = append(chapters, chapterSummary{
			Title:    entry.Title,
			Filename: entry.Filename,
			Minutes:  entry.Duration / 60.0,
			Sections: sections,
		})
	}

	out := BookDetailOutput{
		Title:           detail.Title,
		Identifier:      detail.Identifier,
		Format:          detail.ContentFormat,
		PublicationDate: detail.PublicationDate,
		PageCount:       detail.PageCount,
		Language:        detail.Language,
		URL:             fmt.Sprintf("%s/library/view/-/%s/", oreillyBaseURL, input.ArchiveID),
		Chapters:        chapters,
	}
	return nil, out, nil
}

// --- read_oreilly_chapter ---

// ReadChapterInput is the input for the read_oreilly_chapter tool.
type ReadChapterInput struct {
	ArchiveID string `json:"archive_id" jsonschema_description:"book identifier (e.g. '9781835880302')"`
	Filename  string `json:"filename" jsonschema_description:"chapter filename from book detail (e.g. 'chap01.xhtml')"`
}

// ReadChapterOutput is the output of the read_oreilly_chapter tool.
type ReadChapterOutput struct {
	ArchiveID string `json:"archive_id"`
	Filename  string `json:"filename"`
	Content   string `json:"content"`
	Length    int    `json:"length"`
}

func (s *Server) readOReillyChapter(ctx context.Context, _ *mcp.CallToolRequest, input *ReadChapterInput) (*mcp.CallToolResult, ReadChapterOutput, error) {
	if s.oreilly == nil {
		return nil, ReadChapterOutput{}, fmt.Errorf("O'Reilly search is not configured (ORM_JWT not set)")
	}
	if input.ArchiveID == "" || input.Filename == "" {
		return nil, ReadChapterOutput{}, fmt.Errorf("archive_id and filename are required")
	}

	content, err := s.oreilly.ChapterContent(ctx, input.ArchiveID, input.Filename)
	if err != nil {
		return nil, ReadChapterOutput{}, fmt.Errorf("reading chapter: %w", err)
	}

	// Truncate very long chapters to avoid overwhelming the context window.
	const maxContentLen = 50000
	truncated := content
	if len(truncated) > maxContentLen {
		truncated = truncated[:maxContentLen] + "\n\n[... content truncated at 50,000 characters ...]"
	}

	out := ReadChapterOutput{
		ArchiveID: input.ArchiveID,
		Filename:  input.Filename,
		Content:   truncated,
		Length:    len(content),
	}
	return nil, out, nil
}
