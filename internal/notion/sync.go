package notion

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/koopa0/koopa/internal/knowledge"
)

// SyncResult represents the result of a Notion sync operation.
type SyncResult struct {
	PagesSynced   int
	PagesSkipped  int
	PagesFailed   int
	TotalDuration time.Duration
}

// SyncToKnowledgeStore synchronizes all accessible Notion pages to the knowledge store.
//
// Parameters:
//   - ctx: Context for the operation
//   - client: Notion API client
//   - store: Knowledge store to sync to
//   - maxPages: Maximum number of pages to sync (0 = unlimited)
//
// Returns:
//   - *SyncResult: Summary of the sync operation
//   - error: If sync fails critically (individual page failures are logged but don't stop the sync)
//
// This function:
// 1. Searches for all pages accessible to the Notion integration
// 2. For each page, retrieves its content (blocks)
// 3. Extracts plain text from blocks
// 4. Stores the page in the knowledge store with metadata
func SyncToKnowledgeStore(ctx context.Context, client *Client, store knowledge.VectorStore, maxPages int) (*SyncResult, error) {
	startTime := time.Now()
	result := &SyncResult{}

	slog.Info("starting Notion sync...")

	// Step 1: Search for all pages
	pages, err := client.Search(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to search pages: %w", err)
	}

	slog.Info("found pages in Notion",
		"page_count", len(pages))

	// Apply maxPages limit if specified
	totalPages := len(pages)
	if maxPages > 0 && totalPages > maxPages {
		slog.Info("limiting sync to first N pages",
			"total_available", totalPages,
			"max_pages", maxPages)
		pages = pages[:maxPages]
	}

	// Step 2: Sync each page
	for i, page := range pages {
		pageTitle := ExtractPageTitle(&page)

		slog.Info("syncing page",
			"progress", fmt.Sprintf("%d/%d", i+1, len(pages)),
			"page_id", page.ID,
			"page_title", pageTitle)

		// Get page content (blocks)
		blocks, err := client.GetBlockChildren(ctx, page.ID)
		if err != nil {
			slog.Warn("failed to get page content, skipping",
				"page_id", page.ID,
				"page_title", pageTitle,
				"error", err)
			result.PagesFailed++
			continue
		}

		// Extract text from blocks
		content := ExtractText(blocks)

		// Skip empty pages
		if strings.TrimSpace(content) == "" {
			slog.Info("skipping empty page",
				"page_id", page.ID,
				"page_title", pageTitle)
			result.PagesSkipped++
			continue
		}

		// Create knowledge document
		doc := knowledge.Document{
			ID:      "notion_" + page.ID,
			Content: content,
			Metadata: map[string]string{
				"source_type":      "notion",
				"page_id":          page.ID,
				"page_title":       pageTitle,
				"page_url":         page.URL,
				"last_sync":        time.Now().Format(time.RFC3339),
				"created_time":     page.CreatedTime.Format(time.RFC3339),
				"last_edited_time": page.LastEditedTime.Format(time.RFC3339),
			},
			CreateAt: time.Now(),
		}

		// Add to knowledge store
		if err := store.Add(ctx, doc); err != nil {
			slog.Warn("failed to add page to knowledge store",
				"page_id", page.ID,
				"page_title", pageTitle,
				"error", err)
			result.PagesFailed++
			continue
		}

		result.PagesSynced++
	}

	result.TotalDuration = time.Since(startTime)

	slog.Info("Notion sync completed",
		"pages_synced", result.PagesSynced,
		"pages_skipped", result.PagesSkipped,
		"pages_failed", result.PagesFailed,
		"duration", result.TotalDuration.String())

	return result, nil
}

// ExtractText extracts plain text from an array of blocks.
//
// Parameters:
//   - blocks: Array of Notion blocks
//
// Returns:
//   - string: Concatenated plain text from all blocks
//
// Supported block types:
//   - paragraph, heading_1/2/3, bulleted_list_item, numbered_list_item
//   - code, quote, callout, to_do
func ExtractText(blocks []Block) string {
	var builder strings.Builder

	for _, block := range blocks {
		var text string

		switch block.Type {
		case "paragraph":
			if block.Paragraph != nil {
				text = extractRichText(block.Paragraph.RichText)
			}
		case "heading_1":
			if block.Heading1 != nil {
				text = "# " + extractRichText(block.Heading1.RichText)
			}
		case "heading_2":
			if block.Heading2 != nil {
				text = "## " + extractRichText(block.Heading2.RichText)
			}
		case "heading_3":
			if block.Heading3 != nil {
				text = "### " + extractRichText(block.Heading3.RichText)
			}
		case "bulleted_list_item":
			if block.BulletedListItem != nil {
				text = "• " + extractRichText(block.BulletedListItem.RichText)
			}
		case "numbered_list_item":
			if block.NumberedListItem != nil {
				text = "- " + extractRichText(block.NumberedListItem.RichText)
			}
		case "code":
			if block.Code != nil {
				lang := block.Code.Language
				code := extractRichText(block.Code.RichText)
				text = fmt.Sprintf("```%s\n%s\n```", lang, code)
			}
		case "quote":
			if block.Quote != nil {
				text = "> " + extractRichText(block.Quote.RichText)
			}
		case "callout":
			if block.Callout != nil {
				text = extractRichText(block.Callout.RichText)
			}
		case "to_do":
			if block.ToDo != nil {
				checkbox := "[ ]"
				if block.ToDo.Checked {
					checkbox = "[x]"
				}
				text = checkbox + " " + extractRichText(block.ToDo.RichText)
			}
		default:
			// Unsupported block type, skip silently
			continue
		}

		if text != "" {
			builder.WriteString(text)
			builder.WriteString("\n\n")
		}
	}

	return strings.TrimSpace(builder.String())
}

// extractRichText extracts plain text from an array of RichText objects.
func extractRichText(richTexts []RichText) string {
	var parts []string
	for _, rt := range richTexts {
		parts = append(parts, rt.PlainText)
	}
	return strings.Join(parts, "")
}

// ExtractPageTitle extracts the title from a Notion page.
//
// Parameters:
//   - page: Notion page object
//
// Returns:
//   - string: Page title, or "Untitled" if no title found
func ExtractPageTitle(page *Page) string {
	// Notion pages store title in properties.
	// The title property can have different names, but type is always "title"
	for _, prop := range page.Properties {
		if prop.Type == "title" && len(prop.Title) > 0 {
			return extractRichText(prop.Title)
		}
	}

	// Fallback to ID if no title found
	return "Untitled (ID: " + page.ID + ")"
}

// CountNotionDocuments checks if any Notion documents exist in the knowledge store.
//
// Parameters:
//   - ctx: Context for the operation
//   - store: Knowledge store to query
//
// Returns:
//   - int: Number of Notion documents found (0 if none, >0 if exists)
//   - error: If query fails
//
// Note: Due to chromem-go limitations with large TopK values, this uses a small
// TopK (1) to detect existence. It's sufficient for ShouldSyncOnInit() logic
// which only needs to know "exists" vs "doesn't exist".
func CountNotionDocuments(ctx context.Context, store knowledge.VectorStore) (int, error) {
	// Use a generic query that should match any Notion content
	const query = "document"

	// Use minimal TopK=1 to avoid chromem-go errors with large nResults
	results, err := store.Search(ctx, query,
		knowledge.WithTopK(1),
		knowledge.WithFilter("source_type", "notion"))

	if err != nil {
		// Graceful degradation - assume no Notion documents if search fails
		// This allows sync to proceed if there's an issue
		return 0, nil
	}

	return len(results), nil
}

// ShouldSyncOnInit determines if Notion sync should run on initialization.
//
// Parameters:
//   - ctx: Context for the operation
//   - store: Knowledge store to check
//
// Returns:
//   - bool: true if sync should run (no Notion documents found)
//   - error: If check fails
//
// This implements the "first-time auto-sync" logic.
func ShouldSyncOnInit(ctx context.Context, store knowledge.VectorStore) (bool, error) {
	count, err := CountNotionDocuments(ctx, store)
	if err != nil {
		return false, err
	}

	// Sync if no Notion documents found
	return count == 0, nil
}

// GetSyncStats returns statistics about synced Notion content.
//
// Parameters:
//   - ctx: Context for the operation
//   - store: Knowledge store to query
//
// Returns:
//   - map with stats (total_pages, last_sync_time, etc.)
//   - error: If query fails
//
// Note: Due to chromem-go limitations with large TopK values, this uses a
// conservative TopK=10 to sample documents and find the most recent sync time.
// The total_pages count is approximate.
func GetSyncStats(ctx context.Context, store knowledge.VectorStore) (map[string]string, error) {
	// Use a generic query and small TopK to sample Notion documents
	const query = "document"
	const sampleSize = 10

	results, err := store.Search(ctx, query,
		knowledge.WithTopK(sampleSize),
		knowledge.WithFilter("source_type", "notion"))

	if err != nil {
		return nil, fmt.Errorf("failed to get sync stats: %w", err)
	}

	stats := map[string]string{
		"total_pages": strconv.Itoa(len(results)) + "+", // "+" indicates this is a minimum count
	}

	// Find most recent sync time among the sampled documents
	var mostRecent time.Time
	for _, result := range results {
		if lastSync, exists := result.Document.Metadata["last_sync"]; exists {
			t, err := time.Parse(time.RFC3339, lastSync)
			if err == nil && t.After(mostRecent) {
				mostRecent = t
			}
		}
	}

	if !mostRecent.IsZero() {
		stats["last_sync_time"] = mostRecent.Format(time.RFC3339)
	}

	return stats, nil
}
