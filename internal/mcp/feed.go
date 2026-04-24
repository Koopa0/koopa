package mcp

import (
	"context"
	"errors"
	"fmt"

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

type ManageFeedsOutput struct {
	Feeds  []feed.Feed `json:"feeds,omitempty"`
	Feed   *feed.Feed  `json:"feed,omitempty"`
	Action string      `json:"action"`
}

func (s *Server) manageFeeds(ctx context.Context, _ *mcp.CallToolRequest, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	if s.feeds == nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("feed store not configured")
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
	return nil, ManageFeedsOutput{Feeds: feeds, Action: "list"}, nil
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
	return nil, ManageFeedsOutput{Feed: f, Action: "add"}, nil
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
	return nil, ManageFeedsOutput{Feed: f, Action: "update"}, nil
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
