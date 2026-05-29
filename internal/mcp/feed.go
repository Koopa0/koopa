package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/feed"
)

// mcpMaxTopicIDs caps the number of topic_id values a single manage_feeds
// add/update action may carry. Mirrors the HTTP admin path's bound (see
// internal/feed/handler.go maxTopicIDs). Keeps the junction write size
// bounded and prevents oversized inputs from reaching the store.
const mcpMaxTopicIDs = 20

// --- manage_feeds ---

// ManageFeedsInput is the input for the manage_feeds multiplexer tool.
//
// Schedule is a pointer so update distinguishes omitted ("leave
// unchanged") from explicit. On add the handler treats nil or empty as
// missing and rejects the request before any store call.
//
// TopicIDs is tri-state on update — a nil slice leaves the junction
// untouched, an explicit empty slice clears all associations, and a
// populated list replaces them. On add, nil or empty simply means "no
// topic associations".
type ManageFeedsInput struct {
	Action   string   `json:"action" jsonschema:"required" jsonschema_description:"Action: list, add, update, remove"`
	FeedID   *string  `json:"feed_id,omitempty" jsonschema_description:"Feed UUID (required for update/remove)"`
	URL      *string  `json:"url,omitempty" jsonschema_description:"Feed URL (required for add)"`
	Name     *string  `json:"name,omitempty" jsonschema_description:"Feed name (required for add)"`
	Schedule *string  `json:"schedule,omitempty" jsonschema_description:"One of: hourly, daily, weekly, biweekly, monthly (required for add)"`
	TopicIDs []string `json:"topic_ids,omitempty" jsonschema_description:"Up to 20 topic UUIDs. On update: nil leaves unchanged, [] clears, populated replaces."`
	Enabled  *bool    `json:"enabled,omitempty" jsonschema_description:"Enable/disable feed (for update)"`
}

// FeedSummary is the wire shape for manage_feeds responses. Strips
// admin / pipeline-internal fields that the MCP caller doesn't need:
// filter_config, etag, last_modified, consecutive_failures, last_error,
// disabled_reason, created_at, updated_at. The HTTP admin endpoint
// (internal/feed/handler.go) returns the full feed.Feed for callers
// that DO need pipeline diagnostics. Keeping the MCP payload narrow
// matches the role boundary: agents schedule and inspect by name, not
// by HTTP cache headers.
type FeedSummary struct {
	ID            uuid.UUID  `json:"id"`
	URL           string     `json:"url"`
	Name          string     `json:"name"`
	Schedule      string     `json:"schedule"`
	Topics        []string   `json:"topics"`
	Enabled       bool       `json:"enabled"`
	Priority      string     `json:"priority"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
}

// ManageFeedsOutput is the response shape for manage_feeds actions.
//
// Feeds is initialised to []FeedSummary{} (not nil) for the list action
// so the JSON envelope serialises to "feeds":[] when no rows match.
// json-api rule forbids null on list fields. Total carries the
// feeds-array length so callers don't have to count.
type ManageFeedsOutput struct {
	Feeds  []FeedSummary `json:"feeds"`
	Total  int           `json:"total"`
	Feed   *FeedSummary  `json:"feed,omitempty"`
	Action string        `json:"action"`
}

// toFeedSummary converts a store-side feed.Feed into the wire shape.
func toFeedSummary(f *feed.Feed) FeedSummary {
	return FeedSummary{
		ID:            f.ID,
		URL:           f.URL,
		Name:          f.Name,
		Schedule:      f.Schedule,
		Topics:        f.Topics,
		Enabled:       f.Enabled,
		Priority:      f.Priority,
		LastFetchedAt: f.LastFetchedAt,
	}
}

// toFeedSummaries converts a slice of feed.Feed into the wire shape,
// preserving order and never returning nil.
func toFeedSummaries(feeds []feed.Feed) []FeedSummary {
	out := make([]FeedSummary, len(feeds))
	for i := range feeds {
		out[i] = toFeedSummary(&feeds[i])
	}
	return out
}

func (s *Server) manageFeeds(ctx context.Context, _ *mcp.CallToolRequest, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	if s.feeds == nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("feed store not configured")
	}
	// Identity gate on the mutating actions only; list is read-only and
	// stays open (consistent with the package's read tier). manage_feeds
	// is Destructive — add/update/remove must carry a known author.
	if input.Action != "list" {
		if err := s.requireRegisteredCaller(ctx, "manage_feeds"); err != nil {
			return nil, ManageFeedsOutput{}, err
		}
	}
	switch input.Action {
	case "list":
		return s.listFeeds(ctx)
	case "add":
		return s.addFeed(ctx, input)
	case "update":
		return s.updateFeed(ctx, input)
	case "remove":
		return s.removeFeed(ctx, input)
	default:
		return nil, ManageFeedsOutput{}, fmt.Errorf("invalid action %q (valid: list, add, update, remove)", input.Action)
	}
}

func (s *Server) listFeeds(ctx context.Context) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	feeds, err := s.feeds.Feeds(ctx, nil)
	if err != nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("listing feeds: %w", err)
	}
	summaries := toFeedSummaries(feeds)
	return nil, ManageFeedsOutput{Feeds: summaries, Total: len(summaries), Action: "list"}, nil
}

func (s *Server) addFeed(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	if input.URL == nil || *input.URL == "" {
		return nil, ManageFeedsOutput{}, fmt.Errorf("url is required for add")
	}
	if input.Name == nil || *input.Name == "" {
		return nil, ManageFeedsOutput{}, fmt.Errorf("name is required for add")
	}
	if input.Schedule == nil || *input.Schedule == "" {
		return nil, ManageFeedsOutput{}, fmt.Errorf("schedule is required for add")
	}
	if !feed.ValidSchedule(*input.Schedule) {
		return nil, ManageFeedsOutput{}, fmt.Errorf("invalid schedule value (valid: hourly, daily, weekly, biweekly, monthly)")
	}
	topicIDs, err := parseMCPTopicIDs(input.TopicIDs)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}

	var f *feed.Feed
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		f, createErr = s.feeds.WithTx(tx).CreateFeed(ctx, &feed.CreateParams{
			URL:      *input.URL,
			Name:     *input.Name,
			Schedule: *input.Schedule,
			TopicIDs: topicIDs,
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, feed.ErrTopicNotFound) {
			return nil, ManageFeedsOutput{}, fmt.Errorf("one or more topic_ids do not reference an existing topic")
		}
		if errors.Is(err, feed.ErrConflict) {
			return nil, ManageFeedsOutput{}, fmt.Errorf("feed with this url already exists")
		}
		return nil, ManageFeedsOutput{}, fmt.Errorf("adding feed: %w", err)
	}
	s.logger.Info("manage_feeds", "action", "add", "id", f.ID, "name", f.Name)
	summary := toFeedSummary(f)
	return nil, ManageFeedsOutput{Feed: &summary, Action: "add"}, nil
}

func (s *Server) updateFeed(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}
	if input.Schedule != nil && !feed.ValidSchedule(*input.Schedule) {
		return nil, ManageFeedsOutput{}, fmt.Errorf("invalid schedule value (valid: hourly, daily, weekly, biweekly, monthly)")
	}
	topicIDs, err := parseMCPTopicIDs(input.TopicIDs)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}

	var f *feed.Feed
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var updateErr error
		f, updateErr = s.feeds.WithTx(tx).UpdateFeed(ctx, id, &feed.UpdateParams{
			Schedule: input.Schedule,
			TopicIDs: topicIDs,
			Enabled:  input.Enabled,
		})
		return updateErr
	})
	if err != nil {
		if errors.Is(err, feed.ErrNotFound) {
			return nil, ManageFeedsOutput{}, fmt.Errorf("feed not found")
		}
		if errors.Is(err, feed.ErrTopicNotFound) {
			return nil, ManageFeedsOutput{}, fmt.Errorf("one or more topic_ids do not reference an existing topic")
		}
		return nil, ManageFeedsOutput{}, fmt.Errorf("updating feed: %w", err)
	}
	s.logger.Info("manage_feeds", "action", "update", "id", id)
	summary := toFeedSummary(f)
	return nil, ManageFeedsOutput{Feed: &summary, Action: "update"}, nil
}

func (s *Server) removeFeed(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		return s.feeds.WithTx(tx).DeleteFeed(ctx, id)
	})
	if err != nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("removing feed: %w", err)
	}
	s.logger.Info("manage_feeds", "action", "remove", "id", id)
	return nil, ManageFeedsOutput{Action: "remove"}, nil
}

func parseFeedID(s *string) (uuid.UUID, error) {
	if s == nil || *s == "" {
		return uuid.Nil, fmt.Errorf("feed_id is required")
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		// Intentionally NOT wrapping err with %w. uuid.Parse's error
		// messages ("invalid UUID length: 3", "invalid UUID format")
		// leak internal parser state to MCP callers with no client
		// value — the field name alone is enough to locate the bad
		// input. Applies to every MCP-boundary UUID parse helper.
		return uuid.Nil, fmt.Errorf("invalid feed_id")
	}
	return id, nil
}

// parseMCPTopicIDs validates a slice of topic_id strings and returns
// their parsed UUID form. Mirrors the tri-state contract of the HTTP
// admin path so the store sees identical semantics regardless of
// transport: a nil input returns nil (leave unchanged on update,
// no topics on add), and a non-nil empty slice returns a non-nil
// zero-length slice (clear on update).
//
// On a malformed UUID the error names the offending index without
// wrapping uuid.Parse — see parseFeedID for rationale. The index is
// enough to pinpoint the bad element in the caller's input array.
func parseMCPTopicIDs(raw []string) ([]uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > mcpMaxTopicIDs {
		return nil, fmt.Errorf("too many topic_ids (max %d)", mcpMaxTopicIDs)
	}
	out := make([]uuid.UUID, len(raw))
	for i, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("invalid topic_id at index %d", i)
		}
		out[i] = id
	}
	return out, nil
}
