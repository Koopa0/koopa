package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
)

// --- curate tool ---

// CurateInput is the input for the curate_collected_item tool.
type CurateInput struct {
	CollectedID string   `json:"collected_id" jsonschema_description:"UUID of the collected_data item to curate (required)"`
	Notes       string   `json:"notes,omitempty" jsonschema_description:"personal notes or commentary on why this is valuable"`
	Tags        []string `json:"tags,omitempty" jsonschema_description:"tags for the bookmark"`
}

// CurateOutput is the output of the curate_collected_item tool.
type CurateOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

func (s *Server) curateCollectedItem(ctx context.Context, _ *mcp.CallToolRequest, input CurateInput) (*mcp.CallToolResult, CurateOutput, error) {
	if input.CollectedID == "" {
		return nil, CurateOutput{}, fmt.Errorf("collected_id is required")
	}

	collectedID, err := uuid.Parse(input.CollectedID)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("invalid collected_id: %w", err)
	}

	item, err := s.collected.Item(ctx, collectedID)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("fetching collected item: %w", err)
	}

	if item.Status == collected.StatusCurated {
		return nil, CurateOutput{}, fmt.Errorf("item already curated")
	}

	now := time.Now()
	slug := fmt.Sprintf("bookmark-%s", item.URLHash)
	if item.URLHash == "" {
		slug = fmt.Sprintf("bookmark-%d", now.Unix())
	}

	sourceType := content.SourceExternal
	body := fmt.Sprintf("source: %s\nurl: %s\n\n", item.SourceName, item.SourceURL)
	if input.Notes != "" {
		body += input.Notes + "\n\n"
	}
	if item.OriginalContent != nil && *item.OriginalContent != "" {
		body += "---\n\n" + *item.OriginalContent
	}

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	tags = ensureTag(tags, "bookmark")
	for _, t := range item.Topics {
		tags = ensureTag(tags, t)
	}

	params := &content.CreateParams{
		Slug:        slug,
		Title:       item.Title,
		Body:        body,
		Type:        content.TypeBookmark,
		Status:      content.StatusDraft,
		Tags:        tags,
		Source:      &item.SourceURL,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewLight,
	}

	created, err := s.createContentWithRetry(ctx, params, slug, now)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("creating bookmark content: %w", err)
	}

	if curateErr := s.collected.Curate(ctx, collectedID, created.ID); curateErr != nil {
		s.logger.Error("curate: failed to link collected item", "collected_id", collectedID, "content_id", created.ID, "error", curateErr)
	}

	return nil, CurateOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Title:     created.Title,
		Status:    string(created.Status),
	}, nil
}

// ensureTag returns a copy of tags that includes target, adding it if absent.
func ensureTag(tags []string, target string) []string {
	if tags == nil {
		tags = []string{}
	}
	for _, t := range tags {
		if t == target {
			return tags
		}
	}
	return append(tags, target)
}

// --- feed tools (split from manage_feeds) ---

type feedBrief struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Enabled       bool     `json:"enabled"`
	Schedule      string   `json:"schedule"`
	Topics        []string `json:"topics"`
	LastFetchedAt string   `json:"last_fetched_at,omitempty"`
}

func toFeedBrief(f *feed.Feed) feedBrief {
	fb := feedBrief{
		ID:       f.ID.String(),
		Name:     f.Name,
		URL:      f.URL,
		Enabled:  f.Enabled,
		Schedule: f.Schedule,
		Topics:   f.Topics,
	}
	if f.LastFetchedAt != nil {
		fb.LastFetchedAt = f.LastFetchedAt.Format(time.RFC3339)
	}
	return fb
}

// ListFeedsInput is the input for the list_feeds tool.
type ListFeedsInput struct{}

// ListFeedsOutput is the output for the list_feeds tool.
type ListFeedsOutput struct {
	Feeds []feedBrief `json:"feeds"`
}

func (s *Server) listFeeds(ctx context.Context, _ *mcp.CallToolRequest, _ ListFeedsInput) (*mcp.CallToolResult, ListFeedsOutput, error) {
	feeds, err := s.feeds.Feeds(ctx, nil)
	if err != nil {
		return nil, ListFeedsOutput{}, fmt.Errorf("listing feeds: %w", err)
	}
	briefs := make([]feedBrief, len(feeds))
	for i := range feeds {
		briefs[i] = toFeedBrief(&feeds[i])
	}
	return nil, ListFeedsOutput{Feeds: briefs}, nil
}

// AddFeedInput is the input for the add_feed tool.
type AddFeedInput struct {
	URL      string   `json:"url" jsonschema_description:"feed URL (required)"`
	Name     string   `json:"name" jsonschema_description:"feed name (required)"`
	Schedule string   `json:"schedule,omitempty" jsonschema_description:"daily or weekly (default: daily)"`
	Topics   []string `json:"topics,omitempty" jsonschema_description:"topic tags for the feed"`
}

// AddFeedOutput is the output for the add_feed tool.
type AddFeedOutput struct {
	Feed    feedBrief `json:"feed"`
	Message string    `json:"message"`
}

func (s *Server) addFeed(ctx context.Context, _ *mcp.CallToolRequest, input AddFeedInput) (*mcp.CallToolResult, AddFeedOutput, error) {
	if input.URL == "" || input.Name == "" {
		return nil, AddFeedOutput{}, fmt.Errorf("url and name are required")
	}
	schedule := input.Schedule
	if schedule == "" {
		schedule = feed.ScheduleDaily
	}
	if !feed.ValidSchedule(schedule) {
		return nil, AddFeedOutput{}, fmt.Errorf("invalid schedule %q: use daily, weekly, or hourly_4", schedule)
	}
	created, err := s.feeds.CreateFeed(ctx, &feed.CreateParams{
		URL:      input.URL,
		Name:     input.Name,
		Schedule: schedule,
		Topics:   input.Topics,
	})
	if err != nil {
		if errors.Is(err, feed.ErrConflict) {
			return nil, AddFeedOutput{}, fmt.Errorf("feed with this URL already exists")
		}
		return nil, AddFeedOutput{}, fmt.Errorf("creating feed: %w", err)
	}
	fb := toFeedBrief(created)
	return nil, AddFeedOutput{Feed: fb, Message: "feed created"}, nil
}

// FeedIDInput is shared input for disable_feed, enable_feed, remove_feed.
type FeedIDInput struct {
	FeedID string `json:"feed_id" jsonschema_description:"feed UUID (required)"`
}

// FeedActionOutput is shared output for disable/enable/remove feed operations.
type FeedActionOutput struct {
	Message string `json:"message"`
}

func (s *Server) disableFeed(ctx context.Context, _ *mcp.CallToolRequest, input FeedIDInput) (*mcp.CallToolResult, FeedActionOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, FeedActionOutput{}, err
	}
	enabled := false
	if _, err = s.feeds.UpdateFeed(ctx, id, &feed.UpdateParams{Enabled: &enabled}); err != nil {
		if errors.Is(err, feed.ErrNotFound) {
			return nil, FeedActionOutput{}, fmt.Errorf("feed %s not found", input.FeedID)
		}
		return nil, FeedActionOutput{}, fmt.Errorf("disabling feed: %w", err)
	}
	return nil, FeedActionOutput{Message: fmt.Sprintf("feed %s disabled", input.FeedID)}, nil
}

func (s *Server) enableFeed(ctx context.Context, _ *mcp.CallToolRequest, input FeedIDInput) (*mcp.CallToolResult, FeedActionOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, FeedActionOutput{}, err
	}
	enabled := true
	if _, err = s.feeds.UpdateFeed(ctx, id, &feed.UpdateParams{Enabled: &enabled}); err != nil {
		if errors.Is(err, feed.ErrNotFound) {
			return nil, FeedActionOutput{}, fmt.Errorf("feed %s not found", input.FeedID)
		}
		return nil, FeedActionOutput{}, fmt.Errorf("enabling feed: %w", err)
	}
	return nil, FeedActionOutput{Message: fmt.Sprintf("feed %s enabled", input.FeedID)}, nil
}

func (s *Server) removeFeed(ctx context.Context, _ *mcp.CallToolRequest, input FeedIDInput) (*mcp.CallToolResult, FeedActionOutput, error) {
	id, err := parseFeedID(input.FeedID)
	if err != nil {
		return nil, FeedActionOutput{}, err
	}
	if err := s.feeds.DeleteFeed(ctx, id); err != nil {
		return nil, FeedActionOutput{}, fmt.Errorf("removing feed: %w", err)
	}
	return nil, FeedActionOutput{Message: fmt.Sprintf("feed %s removed", input.FeedID)}, nil
}

func parseFeedID(raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.UUID{}, fmt.Errorf("feed_id is required")
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid feed_id %q: %w", raw, err)
	}
	return id, nil
}

// --- get_collection_stats tool ---

// CollectionStatsInput is the input for the get_collection_stats tool.
type CollectionStatsInput struct {
	FeedID string `json:"feed_id,omitempty" jsonschema_description:"specific feed UUID (omit for global stats)"`
	Days   int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default: 30, max: 90)"`
}

// CollectionStatsOutput is the output for the get_collection_stats tool.
type CollectionStatsOutput struct {
	Feeds  []feedCollectionStat `json:"feeds"`
	Global globalCollectionStat `json:"global"`
	Days   int                  `json:"days"`
}

type feedCollectionStat struct {
	FeedID          string  `json:"feed_id"`
	FeedName        string  `json:"feed_name"`
	TotalItems      int     `json:"total_items"`
	AvgScore        float64 `json:"avg_score"`
	LastCollectedAt string  `json:"last_collected_at,omitempty"`
}

type globalCollectionStat struct {
	TotalItems   int     `json:"total_items"`
	TotalFeeds   int     `json:"total_feeds"`
	AvgScore     float64 `json:"avg_score"`
	UnreadCount  int     `json:"unread_count"`
	CuratedCount int     `json:"curated_count"`
}

func (s *Server) getCollectionStats(ctx context.Context, _ *mcp.CallToolRequest, input CollectionStatsInput) (*mcp.CallToolResult, CollectionStatsOutput, error) {
	days := clamp(input.Days, 1, 90, 30)

	var feedID *uuid.UUID
	if input.FeedID != "" {
		id, err := uuid.Parse(input.FeedID)
		if err != nil {
			return nil, CollectionStatsOutput{}, fmt.Errorf("invalid feed_id %q: %w", input.FeedID, err)
		}
		feedID = &id
	}

	cs, err := s.collected.CollectionStats(ctx, feedID, days)
	if err != nil {
		return nil, CollectionStatsOutput{}, fmt.Errorf("querying collection stats: %w", err)
	}

	feeds := make([]feedCollectionStat, len(cs.Feeds))
	for i := range cs.Feeds {
		f := &cs.Feeds[i]
		feeds[i] = feedCollectionStat{
			FeedID:     f.FeedID.String(),
			FeedName:   f.FeedName,
			TotalItems: f.TotalItems,
			AvgScore:   f.AvgScore,
		}
		if f.LastCollectedAt != nil {
			feeds[i].LastCollectedAt = f.LastCollectedAt.Format(time.RFC3339)
		}
	}

	return nil, CollectionStatsOutput{
		Feeds: feeds,
		Global: globalCollectionStat{
			TotalItems:   cs.Global.TotalItems,
			TotalFeeds:   cs.Global.TotalFeeds,
			AvgScore:     cs.Global.AvgScore,
			UnreadCount:  cs.Global.UnreadCount,
			CuratedCount: cs.Global.CuratedCount,
		},
		Days: days,
	}, nil
}

// --- get_system_status tool ---

// SystemStatusInput is the input for the get_system_status tool.
type SystemStatusInput struct {
	Scope    string `json:"scope,omitempty" jsonschema_description:"summary|pipelines|flows (default: summary)"`
	FlowName string `json:"flow_name,omitempty" jsonschema_description:"filter by flow name (only for scope=flows)"`
	Status   string `json:"status,omitempty" jsonschema_description:"completed|failed|running (only for scope=flows)"`
	Hours    int    `json:"hours,omitempty" jsonschema_description:"lookback hours (default: 24, max: 168)"`
}

// SystemStatusOutput is the output for the get_system_status tool.
type SystemStatusOutput struct {
	Scope      string              `json:"scope"`
	Hours      int                 `json:"hours"`
	FlowStats  *flowStatusSummary  `json:"flow_stats,omitempty"`
	FeedHealth *feedHealthSummary  `json:"feed_health,omitempty"`
	Pipelines  []pipelineSummary   `json:"pipelines,omitempty"`
	FlowRuns   []recentFlowRunItem `json:"flow_runs,omitempty"`
}

type flowStatusSummary struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Running   int `json:"running"`
}

type feedHealthSummary struct {
	Total        int `json:"total"`
	Enabled      int `json:"enabled"`
	FailingFeeds int `json:"failing_feeds"`
}

type pipelineSummary struct {
	FlowName   string  `json:"flow_name"`
	Total      int     `json:"total"`
	Completed  int     `json:"completed"`
	Failed     int     `json:"failed"`
	Running    int     `json:"running"`
	LastRunAt  *string `json:"last_run_at,omitempty"`
	LastStatus *string `json:"last_status,omitempty"`
}

type recentFlowRunItem struct {
	ID        string  `json:"id"`
	FlowName  string  `json:"flow_name"`
	Status    string  `json:"status"`
	Error     *string `json:"error,omitempty"`
	CreatedAt string  `json:"created_at"`
	EndedAt   *string `json:"ended_at,omitempty"`
}

func (s *Server) getSystemStatus(ctx context.Context, _ *mcp.CallToolRequest, input SystemStatusInput) (*mcp.CallToolResult, SystemStatusOutput, error) {
	scope := input.Scope
	if scope == "" {
		scope = "summary"
	}

	hours := clamp(input.Hours, 1, 168, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	out := SystemStatusOutput{Scope: scope, Hours: hours}

	var err error
	switch scope {
	case "summary":
		err = s.statusScopeSummary(ctx, since, &out)
	case "pipelines":
		err = s.statusScopePipelines(ctx, since, &out)
	case "flows":
		err = s.statusScopeFlows(ctx, since, &input, &out)
	default:
		return nil, SystemStatusOutput{}, fmt.Errorf("invalid scope %q: must be summary, pipelines, or flows", scope)
	}
	if err != nil {
		return nil, SystemStatusOutput{}, err
	}

	return nil, out, nil
}

func (s *Server) statusScopeSummary(ctx context.Context, since time.Time, out *SystemStatusOutput) error {
	fs, err := s.systemStatus.FlowRunsSince(ctx, since, nil, nil)
	if err != nil {
		return fmt.Errorf("querying flow stats: %w", err)
	}
	out.FlowStats = &flowStatusSummary{
		Total:     fs.Total,
		Completed: fs.Completed,
		Failed:    fs.Failed,
		Running:   fs.Running,
	}

	fh, err := s.systemStatus.FeedHealth(ctx)
	if err != nil {
		return fmt.Errorf("querying feed health: %w", err)
	}
	out.FeedHealth = &feedHealthSummary{
		Total:        fh.Total,
		Enabled:      fh.Enabled,
		FailingFeeds: fh.FailingFeeds,
	}
	return nil
}

func (s *Server) statusScopePipelines(ctx context.Context, since time.Time, out *SystemStatusOutput) error {
	summaries, err := s.systemStatus.PipelineSummaries(ctx, since)
	if err != nil {
		return fmt.Errorf("querying pipeline summaries: %w", err)
	}
	out.Pipelines = make([]pipelineSummary, len(summaries))
	for i, ps := range summaries {
		out.Pipelines[i] = pipelineSummary{
			FlowName:   ps.FlowName,
			Total:      ps.Total,
			Completed:  ps.Completed,
			Failed:     ps.Failed,
			Running:    ps.Running,
			LastRunAt:  ps.LastRunAt,
			LastStatus: ps.LastStatus,
		}
	}
	return nil
}

func (s *Server) statusScopeFlows(ctx context.Context, since time.Time, input *SystemStatusInput, out *SystemStatusOutput) error {
	var flowName, status *string
	if input.FlowName != "" {
		flowName = &input.FlowName
	}
	if input.Status != "" {
		switch input.Status {
		case "completed", "failed", "running":
			status = &input.Status
		default:
			return fmt.Errorf("invalid status %q: must be completed, failed, or running", input.Status)
		}
	}

	runs, err := s.systemStatus.RecentFlowRuns(ctx, since, flowName, status, 50)
	if err != nil {
		return fmt.Errorf("querying recent flow runs: %w", err)
	}
	out.FlowRuns = make([]recentFlowRunItem, len(runs))
	for i, r := range runs {
		out.FlowRuns[i] = recentFlowRunItem{
			ID:        r.ID,
			FlowName:  r.FlowName,
			Status:    r.Status,
			Error:     r.Error,
			CreatedAt: r.CreatedAt,
			EndedAt:   r.EndedAt,
		}
	}
	return nil
}

// --- trigger_pipeline tool ---

// TriggerPipelineInput is the input for the trigger_pipeline tool.
type TriggerPipelineInput struct {
	Pipeline string `json:"pipeline" jsonschema_description:"rss_collector|notion_sync (required)"`
}

// TriggerPipelineOutput is the output for the trigger_pipeline tool.
type TriggerPipelineOutput struct {
	Triggered bool   `json:"triggered"`
	Pipeline  string `json:"pipeline"`
	Message   string `json:"message"`
}

// triggerCooldown is the minimum interval between triggers of the same pipeline.
const triggerCooldown = 5 * time.Minute

func (s *Server) triggerPipeline(ctx context.Context, _ *mcp.CallToolRequest, input TriggerPipelineInput) (*mcp.CallToolResult, TriggerPipelineOutput, error) {
	switch input.Pipeline {
	case "rss_collector", "notion_sync":
		// valid
	case "":
		return nil, TriggerPipelineOutput{}, fmt.Errorf("pipeline is required: valid values are rss_collector, notion_sync")
	default:
		return nil, TriggerPipelineOutput{}, fmt.Errorf("invalid pipeline %q: valid values are rss_collector, notion_sync", input.Pipeline)
	}

	// Rate limit check (mutex-protected for HTTP transport safety).
	s.triggerMu.Lock()
	if last, ok := s.lastTrigger[input.Pipeline]; ok {
		if time.Since(last) < triggerCooldown {
			remaining := triggerCooldown - time.Since(last)
			s.triggerMu.Unlock()
			return nil, TriggerPipelineOutput{
				Triggered: false,
				Pipeline:  input.Pipeline,
				Message:   fmt.Sprintf("rate limited: try again in %s", remaining.Truncate(time.Second)),
			}, nil
		}
	}
	s.lastTrigger[input.Pipeline] = time.Now()
	s.triggerMu.Unlock()

	switch input.Pipeline {
	case "rss_collector":
		s.pipelineTrigger.TriggerCollect(ctx)
	case "notion_sync":
		s.pipelineTrigger.TriggerNotionSync(ctx)
	}

	return nil, TriggerPipelineOutput{
		Triggered: true,
		Pipeline:  input.Pipeline,
		Message:   "pipeline triggered successfully",
	}, nil
}
