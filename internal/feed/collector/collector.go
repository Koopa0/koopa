// Package collector fetches RSS feeds and writes new items to collected_data.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mmcdole/gofeed"

	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/monitor"
)

const (
	maxContentLen       = 5000     // truncate original content for scoring
	maxFeedResponseSize = 10 << 20 // 10 MB
	requestTimeout      = 30 * time.Second
	maxRedirects        = 3
	userAgent           = "koopa0.dev/rss-collector (+https://koopa0.dev)"
)

// Collector fetches RSS feeds and writes new items to collected_data.
type Collector struct {
	writer   *entry.Store
	feeds    *feed.Store
	keywords *monitor.Store
	client   *http.Client
	limiter  *DomainLimiter
	logger   *slog.Logger
}

// New returns a Collector.
func New(writer *entry.Store, feeds *feed.Store, keywords *monitor.Store, logger *slog.Logger) *Collector {
	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}
			return nil
		},
	}
	return &Collector{
		writer:   writer,
		feeds:    feeds,
		keywords: keywords,
		client:   client,
		limiter:  NewDomainLimiter(2 * time.Second),
		logger:   logger,
	}
}

// Stop releases resources held by the Collector, including the background
// cleanup goroutine in the domain rate limiter.
func (c *Collector) Stop() {
	c.limiter.Stop()
}

// FetchFeed fetches a single feed and returns IDs of newly created collected_data rows.
func (c *Collector) FetchFeed(ctx context.Context, f *feed.Feed) ([]uuid.UUID, error) {
	logger := c.logger.With("feed_id", f.ID, "feed_name", f.Name)

	if err := c.limiter.Wait(ctx, f.URL); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	if err := validateFeedURL(f.URL); err != nil {
		return nil, err
	}

	resp, err := c.doFeedRequest(ctx, f)
	if err != nil {
		if fErr := c.feeds.IncrementFailure(ctx, f.ID, err.Error()); fErr != nil {
			logger.Error("incrementing failure after fetch error", "error", fErr)
		}
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort

	parsed, err := c.handleFeedResponse(ctx, resp, f, logger)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil // 304 Not Modified
	}

	keywords := c.loadKeywords(ctx, logger)
	newIDs := c.processItems(ctx, parsed.Items, f, keywords, logger)

	logger.Info("feed fetched", "total_items", len(parsed.Items), "new_items", len(newIDs))
	return newIDs, nil
}

// validateFeedURL validates the URL scheme to prevent SSRF.
func validateFeedURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid feed url scheme: %s", rawURL)
	}
	host := parsedURL.Hostname()
	// Block private/internal hosts to prevent SSRF.
	blocked := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
		"169.254.169.254", // AWS/GCP metadata
		"metadata.google.internal",
	}
	for _, b := range blocked {
		if strings.EqualFold(host, b) {
			return fmt.Errorf("feed url host %q is blocked (internal address)", host)
		}
	}
	// Block 10.x, 172.16-31.x, 192.168.x private ranges.
	if strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.") {
		return fmt.Errorf("feed url host %q is blocked (private network)", host)
	}
	return nil
}

// doFeedRequest builds and executes the HTTP request for a feed.
func (c *Collector) doFeedRequest(ctx context.Context, f *feed.Feed) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	if f.Etag != "" {
		req.Header.Set("If-None-Match", f.Etag)
	}
	if f.LastModified != "" {
		req.Header.Set("If-Modified-Since", f.LastModified)
	}
	return c.client.Do(req)
}

// handleFeedResponse handles status codes and parses the feed body.
// Returns nil parsed on 304 Not Modified.
func (c *Collector) handleFeedResponse(ctx context.Context, resp *http.Response, f *feed.Feed, logger *slog.Logger) (*gofeed.Feed, error) {
	if resp.StatusCode == http.StatusNotModified {
		etag := resp.Header.Get("ETag")
		lm := resp.Header.Get("Last-Modified")
		if rErr := c.feeds.ResetFailure(ctx, f.ID, etag, lm); rErr != nil {
			logger.Error("resetting failure after 304", "error", rErr)
		}
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("unexpected status: %d", resp.StatusCode)
		if fErr := c.feeds.IncrementFailure(ctx, f.ID, errMsg); fErr != nil {
			logger.Error("incrementing failure after bad status", "error", fErr)
		}
		return nil, fmt.Errorf("fetching feed: %s", errMsg)
	}

	parser := gofeed.NewParser()
	parsed, err := parser.Parse(io.LimitReader(resp.Body, maxFeedResponseSize))
	if err != nil {
		errMsg := fmt.Sprintf("parsing feed: %v", err)
		if fErr := c.feeds.IncrementFailure(ctx, f.ID, errMsg); fErr != nil {
			logger.Error("incrementing failure after parse error", "error", fErr)
		}
		return nil, fmt.Errorf("parsing feed: %w", err)
	}

	etag := resp.Header.Get("ETag")
	lm := resp.Header.Get("Last-Modified")
	if rErr := c.feeds.ResetFailure(ctx, f.ID, etag, lm); rErr != nil {
		logger.Error("resetting failure after successful fetch", "error", rErr)
	}

	return parsed, nil
}

// processItems deduplicates, scores, and stores new feed items.
func (c *Collector) processItems(ctx context.Context, items []*gofeed.Item, f *feed.Feed, keywords []string, logger *slog.Logger) []uuid.UUID {
	var newIDs []uuid.UUID
	for _, item := range items {
		if item.Link == "" {
			continue
		}

		tags := append([]string{}, item.Categories...)
		if f.Filter.Skip(item.Link, item.Title, tags) {
			continue
		}

		id := c.tryCreateItem(ctx, item, f, tags, keywords, logger)
		if id != nil {
			newIDs = append(newIDs, *id)
		}
	}
	return newIDs
}

// tryCreateItem attempts to create a single collected item, returning nil if skipped.
func (c *Collector) tryCreateItem(ctx context.Context, item *gofeed.Item, f *feed.Feed, tags, keywords []string, logger *slog.Logger) *uuid.UUID {
	urlHash := hashURL(item.Link)

	if _, err := c.writer.ItemByURLHash(ctx, urlHash); err == nil {
		return nil // already exists
	} else if !errors.Is(err, entry.ErrNotFound) {
		logger.Error("checking url hash dedup", "url", item.Link, "error", err)
		return nil
	}

	content := itemContent(item)
	if len(content) > maxContentLen {
		content = content[:maxContentLen]
	}

	score := Score(item.Title, content, tags, keywords)

	cd, err := c.writer.CreateItem(ctx, &entry.CreateParams{
		SourceURL:       item.Link,
		SourceName:      f.Name,
		Title:           item.Title,
		OriginalContent: &content,
		Topics:          f.Topics,
		URLHash:         urlHash,
		FeedID:          &f.ID,
		RelevanceScore:  score,
	})
	if err != nil {
		if !errors.Is(err, entry.ErrConflict) {
			logger.Error("creating collected data", "url", item.Link, "error", err)
		}
		return nil
	}
	return &cd.ID
}

// hashURL returns the SHA-256 hex hash of a normalized URL.
func hashURL(rawURL string) string {
	normalized := normalizeURL(rawURL)
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// normalizeURL lowercases scheme+host, strips trailing slash, and removes tracking params.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Fragment = ""

	// strip tracking params
	q := u.Query()
	for key := range q {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "utm_") {
			q.Del(key)
		}
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// loadKeywords returns normalized tracking keywords for scoring (best-effort, never fails).
func (c *Collector) loadKeywords(ctx context.Context, logger *slog.Logger) []string {
	if c.keywords == nil {
		return nil
	}
	kw, err := c.keywords.Keywords(ctx)
	if err != nil {
		logger.Error("loading tracking keywords", "error", err)
		return nil
	}
	return NormalizeKeywords(kw)
}

// itemContent extracts the best available content from a feed item.
func itemContent(item *gofeed.Item) string {
	if item.Content != "" {
		return item.Content
	}
	return item.Description
}
