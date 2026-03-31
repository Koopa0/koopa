package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/oreilly"
)

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
		return nil, SearchOReillyOutput{}, fmt.Errorf("oreilly search is not configured (ORM_JWT not set)")
	}
	if input.Query == "" {
		return nil, SearchOReillyOutput{}, fmt.Errorf("query is required")
	}
	if len(input.Query) > maxQueryLen {
		return nil, SearchOReillyOutput{}, fmt.Errorf("query too long (max %d characters)", maxQueryLen)
	}

	limit := clamp(input.Limit, 1, 50, 10)

	result, err := s.oreilly.Search(ctx, &oreilly.SearchParams{
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
			URL:           oreilly.BaseURL + item.WebURL,
			CoverURL:      item.CoverURL,
			Description:   desc,
			AverageRating: float64(item.AverageRating) / 1000.0,
			Topics:        topics,
		})
	}
	return nil, out, nil
}

// --- oreilly_book_detail ---

// BookDetailInput is the input for the oreilly_book_detail tool.
type BookDetailInput struct {
	ArchiveID string `json:"archive_id" jsonschema_description:"book identifier from search results (e.g. '9781835880302')"`
}

// BookDetailOutput is the output of the oreilly_book_detail tool.
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
		return nil, BookDetailOutput{}, fmt.Errorf("oreilly search is not configured (ORM_JWT not set)")
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
		URL:             fmt.Sprintf("%s/library/view/-/%s/", oreilly.BaseURL, input.ArchiveID),
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
		return nil, ReadChapterOutput{}, fmt.Errorf("oreilly search is not configured (ORM_JWT not set)")
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
