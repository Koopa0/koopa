// Package collector fetches RSS feeds and writes new items to collected_data.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mmcdole/gofeed"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/feed"
)

const (
	maxContentLen  = 5000 // truncate original content for scoring
	requestTimeout = 30 * time.Second
	maxRedirects   = 3
	userAgent      = "koopa0.dev/rss-collector (+https://koopa0.dev)"
)

// CollectedWriter creates collected data records.
type CollectedWriter interface {
	CreateCollectedData(ctx context.Context, p collected.CreateParams) (*collected.CollectedData, error)
	CollectedDataByURLHash(ctx context.Context, urlHash string) (*collected.CollectedData, error)
}

// FeedUpdater updates feed status after fetch.
type FeedUpdater interface {
	IncrementFailure(ctx context.Context, id uuid.UUID, errMsg string) error
	ResetFailure(ctx context.Context, id uuid.UUID, etag, lastModified string) error
}

// Collector fetches RSS feeds and writes new items to collected_data.
type Collector struct {
	writer  CollectedWriter
	feeds   FeedUpdater
	client  *http.Client
	limiter *DomainLimiter
	logger  *slog.Logger
}

// New returns a Collector.
func New(writer CollectedWriter, feeds FeedUpdater, logger *slog.Logger) *Collector {
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
		writer:  writer,
		feeds:   feeds,
		client:  client,
		limiter: NewDomainLimiter(2 * time.Second),
		logger:  logger,
	}
}

// FetchFeed fetches a single feed and returns IDs of newly created collected_data rows.
func (c *Collector) FetchFeed(ctx context.Context, f feed.Feed) ([]uuid.UUID, error) {
	logger := c.logger.With("feed_id", f.ID, "feed_name", f.Name)

	if err := c.limiter.Wait(ctx, f.URL); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	// validate URL scheme to prevent SSRF via file://, gopher://, etc.
	parsedURL, err := url.Parse(f.URL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid feed url scheme: %s", f.URL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
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

	resp, err := c.client.Do(req)
	if err != nil {
		if fErr := c.feeds.IncrementFailure(ctx, f.ID, err.Error()); fErr != nil {
			logger.Error("incrementing failure after fetch error", "error", fErr)
		}
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort

	// 304 Not Modified — nothing new
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
	parsed, err := parser.Parse(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("parsing feed: %v", err)
		if fErr := c.feeds.IncrementFailure(ctx, f.ID, errMsg); fErr != nil {
			logger.Error("incrementing failure after parse error", "error", fErr)
		}
		return nil, fmt.Errorf("parsing feed: %w", err)
	}

	// reset failure counter on successful parse
	etag := resp.Header.Get("ETag")
	lm := resp.Header.Get("Last-Modified")
	if rErr := c.feeds.ResetFailure(ctx, f.ID, etag, lm); rErr != nil {
		logger.Error("resetting failure after successful fetch", "error", rErr)
	}

	var newIDs []uuid.UUID
	for _, item := range parsed.Items {
		if item.Link == "" {
			continue
		}

		// extract tags from RSS categories
		tags := append([]string{}, item.Categories...)

		if f.Filter.Skip(item.Link, item.Title, tags) {
			continue
		}

		urlHash := hashURL(item.Link)

		// dedup by URL hash
		if _, err := c.writer.CollectedDataByURLHash(ctx, urlHash); err == nil {
			// already exists, skip
			continue
		} else if !errors.Is(err, collected.ErrNotFound) {
			logger.Error("checking url hash dedup", "url", item.Link, "error", err)
			continue
		}

		// extract content, truncate for scoring
		content := itemContent(item)
		if len(content) > maxContentLen {
			content = content[:maxContentLen]
		}

		cd, err := c.writer.CreateCollectedData(ctx, collected.CreateParams{
			SourceURL:       item.Link,
			SourceName:      f.Name,
			Title:           item.Title,
			OriginalContent: &content,
			Topics:          f.Topics,
			URLHash:         urlHash,
			FeedID:          &f.ID,
		})
		if err != nil {
			// skip duplicates from race conditions
			if errors.Is(err, collected.ErrConflict) {
				continue
			}
			logger.Error("creating collected data", "url", item.Link, "error", err)
			continue
		}
		newIDs = append(newIDs, cd.ID)
	}

	logger.Info("feed fetched", "total_items", len(parsed.Items), "new_items", len(newIDs))
	return newIDs, nil
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

// itemContent extracts the best available content from a feed item.
func itemContent(item *gofeed.Item) string {
	if item.Content != "" {
		return item.Content
	}
	return item.Description
}
