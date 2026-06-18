// Copyright 2026 Koopa. All rights reserved.

// Package collector fetches RSS feeds and writes new items to feed_entries.
package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/mmcdole/gofeed"

	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/entry"
	koopaurl "github.com/Koopa0/koopa/internal/url"
)

const (
	maxContentLen       = 5000     // truncate original content for scoring
	maxFeedResponseSize = 10 << 20 // 10 MB
	requestTimeout      = 30 * time.Second
	maxRedirects        = 3
	userAgent           = "koopa0.dev/rss-collector (+https://koopa0.dev)"
)

// Collector fetches RSS feeds and writes new items to feed_entries.
type Collector struct {
	writer  *entry.Store
	feeds   *feed.Store
	client  *http.Client
	limiter *DomainLimiter
	logger  *slog.Logger
}

// New returns a Collector.
func New(writer *entry.Store, feeds *feed.Store, logger *slog.Logger) *Collector {
	// The guarded transport blocks internal addresses at connect time (see
	// guardedDialContext); the remaining fields mirror http.DefaultTransport's
	// connection-pool and timeout defaults.
	transport := &http.Transport{
		DialContext:           guardedDialContext(&net.Dialer{Timeout: 10 * time.Second}),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
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

// Stop releases resources held by the Collector, including the background
// cleanup goroutine in the domain rate limiter.
func (c *Collector) Stop() {
	c.limiter.Stop()
}

// FetchFeed fetches a single feed and returns IDs of newly created feed_entries rows.
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

	newIDs := c.processItems(ctx, parsed.Items, f, nil, logger)

	logger.Info("feed fetched", "total_items", len(parsed.Items), "new_items", len(newIDs))
	return newIDs, nil
}

// validateFeedURL is a cheap pre-flight check on a feed URL: it must be
// http/https, carry no userinfo (which can disguise the real host, e.g.
// http://trusted@evil.example/), and have a host. The authoritative SSRF
// control is guardedDialContext, which blocks internal addresses at connect
// time — covering alternate IP encodings, IPv6, DNS rebinding, and redirect
// targets that a hostname-string check cannot. This only rejects obviously
// malformed URLs fast, before any DNS lookup or dial.
func validateFeedURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid feed url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid feed url scheme %q (only http and https are allowed)", parsedURL.Scheme)
	}
	if parsedURL.User != nil {
		return fmt.Errorf("feed url must not contain userinfo")
	}
	if parsedURL.Hostname() == "" {
		return fmt.Errorf("feed url has no host")
	}
	return nil
}

// guardedDialContext returns a DialContext that resolves the target host and
// refuses to connect when any resolved address is internal (see isInternalIP).
// It dials the validated IP directly so a second resolution cannot rebind the
// connection to an internal address between the check and the connect
// (DNS-rebinding defence). The transport calls DialContext for every
// connection — including each redirect hop — so this is the single chokepoint
// that closes SSRF for the whole fetch path.
func guardedDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("splitting dial address: %w", err)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", host, err)
		}
		for _, ip := range ips {
			if isInternalIP(ip.IP) {
				return nil, fmt.Errorf("refusing to connect to internal address %s for host %q", ip.IP, host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// cgnatRange is RFC 6598 shared address space (100.64.0.0/10) for carrier-grade
// NAT. net.IP.IsPrivate covers only RFC 1918, so this range is blocked
// explicitly as defence-in-depth.
var cgnatRange = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// isInternalIP reports whether ip is in a range a server-side fetch must never
// reach: loopback (127/8, ::1), private (10/8, 172.16/12, 192.168/16 and the
// IPv6 ULA fc00::/7), CGNAT (100.64/10), link-local (169.254/16 incl. the
// cloud-metadata 169.254.169.254, and fe80::/10), unspecified (0.0.0.0, ::),
// or multicast. IPv4-mapped IPv6 forms (::ffff:127.0.0.1) are normalised by
// the net.IP methods, so they are covered too.
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		cgnatRange.Contains(ip)
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
	urlHash, err := koopaurl.Hash(item.Link)
	if err != nil {
		logger.Warn("skipping item with unhashable url", "url", item.Link, "error", err)
		return nil
	}

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
		Title:           item.Title,
		OriginalContent: content,
		URLHash:         urlHash,
		FeedID:          &f.ID,
		RelevanceScore:  float64(score),
		PublishedAt:     item.PublishedParsed,
	})
	if err != nil {
		if !errors.Is(err, entry.ErrConflict) {
			logger.Error("creating collected data", "url", item.Link, "error", err)
		}
		return nil
	}
	return &cd.ID
}

// itemContent extracts the best available content from a feed item.
func itemContent(item *gofeed.Item) string {
	if item.Content != "" {
		return item.Content
	}
	return item.Description
}
