package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
	fs, err := s.stats.FlowRunsSince(ctx, since, nil, nil)
	if err != nil {
		return fmt.Errorf("querying flow stats: %w", err)
	}
	out.FlowStats = &flowStatusSummary{
		Total:     fs.Total,
		Completed: fs.Completed,
		Failed:    fs.Failed,
		Running:   fs.Running,
	}

	fh, err := s.stats.FeedHealth(ctx)
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
	summaries, err := s.stats.PipelineSummaries(ctx, since)
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

	runs, err := s.stats.RecentFlowRuns(ctx, since, flowName, status, 50)
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
