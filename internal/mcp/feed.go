package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/feed"
)

// --- manage_feeds ---

type ManageFeedsInput struct {
	Action  string  `json:"action" jsonschema:"required" jsonschema_description:"Action: list, add, update, remove"`
	FeedID  *string `json:"feed_id,omitempty" jsonschema_description:"Feed UUID (required for update/remove)"`
	URL     *string `json:"url,omitempty" jsonschema_description:"Feed URL (required for add)"`
	Name    *string `json:"name,omitempty" jsonschema_description:"Feed name (required for add)"`
	Enabled *bool   `json:"enabled,omitempty" jsonschema_description:"Enable/disable feed (for update)"`
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
		return s.mfList(ctx)
	case "add":
		return s.mfAdd(ctx, input)
	case "update":
		return s.mfUpdate(ctx, input)
	case "remove":
		return s.mfRemove(ctx, input)
	default:
		return nil, ManageFeedsOutput{}, fmt.Errorf("invalid action %q (valid: list, add, update, remove)", input.Action)
	}
}

func (s *Server) mfList(ctx context.Context) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	feeds, err := s.feeds.Feeds(ctx, nil)
	if err != nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("listing feeds: %w", err)
	}
	return nil, ManageFeedsOutput{Feeds: feeds, Action: "list"}, nil
}

func (s *Server) mfAdd(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	if input.URL == nil || *input.URL == "" {
		return nil, ManageFeedsOutput{}, fmt.Errorf("url is required for add")
	}
	if input.Name == nil || *input.Name == "" {
		return nil, ManageFeedsOutput{}, fmt.Errorf("name is required for add")
	}
	f, err := s.feeds.CreateFeed(ctx, &feed.CreateParams{
		URL:  *input.URL,
		Name: *input.Name,
	})
	if err != nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("adding feed: %w", err)
	}
	s.logger.Info("manage_feeds", "action", "add", "id", f.ID, "name", f.Name)
	return nil, ManageFeedsOutput{Feed: f, Action: "add"}, nil
}

func (s *Server) mfUpdate(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}
	f, err := s.feeds.UpdateFeed(ctx, id, &feed.UpdateParams{
		Enabled: input.Enabled,
	})
	if err != nil {
		return nil, ManageFeedsOutput{}, fmt.Errorf("updating feed: %w", err)
	}
	s.logger.Info("manage_feeds", "action", "update", "id", id)
	return nil, ManageFeedsOutput{Feed: f, Action: "update"}, nil
}

func (s *Server) mfRemove(ctx context.Context, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, ManageFeedsOutput{}, err
	}
	if err := s.feeds.DeleteFeed(ctx, id); err != nil {
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
		return uuid.Nil, fmt.Errorf("invalid feed_id: %w", err)
	}
	return id, nil
}
