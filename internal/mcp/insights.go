package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/session"
)

// --- get_active_insights ---

// ActiveInsightsInput is the input for the get_active_insights tool.
type ActiveInsightsInput struct {
	Status  string `json:"status,omitempty" jsonschema_description:"unverified, verified, invalidated, or all (default unverified)"`
	Project string `json:"project,omitempty" jsonschema_description:"filter by project slug"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max insights to return (default 10)"`
}

// ActiveInsightsOutput is the output of the get_active_insights tool.
type ActiveInsightsOutput struct {
	Insights        []insightEntry `json:"insights"`
	Total           int            `json:"total"`
	UnverifiedCount int64          `json:"unverified_count"`
}

type insightEntry struct {
	ID                    int64    `json:"id"`
	CreatedAt             string   `json:"created_at"`
	Content               string   `json:"content"`
	Hypothesis            string   `json:"hypothesis,omitempty"`
	Status                string   `json:"status"`
	Category              string   `json:"category,omitempty"`
	SupportingEvidence    []string `json:"supporting_evidence"`
	CounterEvidence       []string `json:"counter_evidence,omitempty"`
	SourceDates           []string `json:"source_dates"`
	Project               string   `json:"project,omitempty"`
	Tags                  []string `json:"tags"`
	Conclusion            string   `json:"conclusion,omitempty"`
	InvalidationCondition string   `json:"invalidation_condition,omitempty"`
}

func (s *Server) activeInsights(ctx context.Context, _ *mcp.CallToolRequest, input ActiveInsightsInput) (*mcp.CallToolResult, ActiveInsightsOutput, error) {
	if s.sessions == nil {
		return nil, ActiveInsightsOutput{}, fmt.Errorf("session notes not configured")
	}

	// Lazy auto-archive: verified/invalidated insights older than 14 days → archived
	if s.sessions != nil {
		cutoff := time.Now().AddDate(0, 0, -14)
		if n, err := s.sessions.ArchiveStaleInsights(ctx, cutoff); err != nil {
			s.logger.Error("get_active_insights: auto-archive", "error", err)
		} else if n > 0 {
			s.logger.Info("auto-archived stale insights", "count", n)
		}
	}

	status := input.Status
	if status == "" {
		status = "unverified"
	}
	limit := clamp(input.Limit, 1, 100, 10)

	var statusFilter *string
	if status != "all" {
		statusFilter = &status
	}

	var projectFilter *string
	if input.Project != "" {
		projectFilter = &input.Project
	}

	notes, err := s.sessions.InsightsByStatus(ctx, statusFilter, projectFilter, int32(min(limit, 1000))) //nolint:gosec // limit is bounded by min()
	if err != nil {
		return nil, ActiveInsightsOutput{}, fmt.Errorf("querying insights: %w", err)
	}

	unverifiedStatus := "unverified"
	unverifiedCount, countErr := s.sessions.CountInsightsByStatus(ctx, &unverifiedStatus)
	if countErr != nil {
		s.logger.Error("get_active_insights: counting unverified", "error", countErr)
	}

	insights := make([]insightEntry, 0, len(notes))
	for i := range notes {
		insights = append(insights, parseInsightNote(&notes[i]))
	}

	return nil, ActiveInsightsOutput{
		Insights:        insights,
		Total:           len(insights),
		UnverifiedCount: unverifiedCount,
	}, nil
}

// parseInsightNote extracts structured fields from an insight note's metadata.
func parseInsightNote(n *session.Note) insightEntry {
	entry := insightEntry{
		ID:                 n.ID,
		CreatedAt:          n.CreatedAt.Format(time.DateOnly),
		Content:            n.Content,
		SupportingEvidence: []string{},
		Tags:               []string{},
	}

	if len(n.Metadata) == 0 {
		return entry
	}

	var meta struct {
		Hypothesis            string   `json:"hypothesis"`
		Status                string   `json:"status"`
		Category              string   `json:"category"`
		SupportingEvidence    []string `json:"supporting_evidence"`
		Evidence              []string `json:"evidence"` // legacy fallback
		CounterEvidence       []string `json:"counter_evidence"`
		SourceDates           []string `json:"source_dates"`
		Project               string   `json:"project"`
		Tags                  []string `json:"tags"`
		Conclusion            string   `json:"conclusion"`
		InvalidationCondition string   `json:"invalidation_condition"`
	}
	if err := json.Unmarshal(n.Metadata, &meta); err != nil {
		return entry
	}

	entry.Hypothesis = meta.Hypothesis
	entry.Status = meta.Status
	entry.Category = meta.Category
	entry.Project = meta.Project
	entry.Conclusion = meta.Conclusion
	entry.InvalidationCondition = meta.InvalidationCondition

	// Backward compatible: prefer supporting_evidence, fallback to evidence
	if meta.SupportingEvidence != nil {
		entry.SupportingEvidence = meta.SupportingEvidence
	} else if meta.Evidence != nil {
		entry.SupportingEvidence = meta.Evidence
	}
	if meta.CounterEvidence != nil {
		entry.CounterEvidence = meta.CounterEvidence
	}
	if meta.SourceDates != nil {
		entry.SourceDates = meta.SourceDates
	} else {
		entry.SourceDates = []string{}
	}
	if meta.Tags != nil {
		entry.Tags = meta.Tags
	}

	return entry
}

// --- update_insight ---

// UpdateInsightInput is the input for the update_insight tool.
type UpdateInsightInput struct {
	InsightID             int64  `json:"insight_id" jsonschema_description:"session_note ID of the insight (required)"`
	Status                string `json:"status,omitempty" jsonschema_description:"unverified, verified, invalidated, or archived"`
	AppendEvidence        string `json:"append_evidence,omitempty" jsonschema_description:"new supporting evidence to append"`
	AppendCounterEvidence string `json:"append_counter_evidence,omitempty" jsonschema_description:"counter-evidence to append"`
	Conclusion            string `json:"conclusion,omitempty" jsonschema_description:"conclusion after verification"`
}

// UpdateInsightOutput is the output of the update_insight tool.
type UpdateInsightOutput struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	Evidence   int    `json:"evidence_count"`
	Conclusion string `json:"conclusion,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

func (s *Server) updateInsight(ctx context.Context, _ *mcp.CallToolRequest, input UpdateInsightInput) (*mcp.CallToolResult, UpdateInsightOutput, error) {
	if err := validateInsightInput(input); err != nil {
		return nil, UpdateInsightOutput{}, err
	}
	if s.sessions == nil {
		return nil, UpdateInsightOutput{}, fmt.Errorf("session notes not configured")
	}

	// Read current note
	note, err := s.sessions.NoteByID(ctx, input.InsightID)
	if err != nil {
		return nil, UpdateInsightOutput{}, fmt.Errorf("insight %d not found: %w", input.InsightID, err)
	}
	if note.NoteType != "insight" {
		return nil, UpdateInsightOutput{}, fmt.Errorf("note %d is type %q, not insight", input.InsightID, note.NoteType)
	}

	// Parse existing metadata
	meta, err := parseInsightMetadata(note.Metadata)
	if err != nil {
		return nil, UpdateInsightOutput{}, err
	}

	// Apply updates
	applyInsightUpdates(meta, input)

	// Marshal and update
	updatedMetadata, marshalErr := json.Marshal(meta)
	if marshalErr != nil {
		return nil, UpdateInsightOutput{}, fmt.Errorf("marshaling updated metadata: %w", marshalErr)
	}

	updated, updateErr := s.sessions.UpdateNoteMetadata(ctx, &session.UpdateMetadataParams{
		ID:       input.InsightID,
		Metadata: updatedMetadata,
	})
	if updateErr != nil {
		return nil, UpdateInsightOutput{}, fmt.Errorf("updating insight: %w", updateErr)
	}

	evidenceCount := countEvidence(updated.Metadata)
	currentStatus, _ := meta["status"].(string)
	conclusion, _ := meta["conclusion"].(string)

	s.logger.Info("insight updated via mcp",
		"id", input.InsightID,
		"status", currentStatus,
		"evidence_count", evidenceCount,
	)

	return nil, UpdateInsightOutput{
		ID:         updated.ID,
		Status:     currentStatus,
		Evidence:   evidenceCount,
		Conclusion: conclusion,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}, nil
}

// validateInsightInput checks required fields and status validity.
func validateInsightInput(input UpdateInsightInput) error {
	if input.InsightID == 0 {
		return fmt.Errorf("insight_id is required")
	}
	if input.Status == "" && input.AppendEvidence == "" && input.AppendCounterEvidence == "" && input.Conclusion == "" {
		return fmt.Errorf("at least one of status, append_evidence, append_counter_evidence, or conclusion is required")
	}
	if input.Status != "" {
		switch input.Status {
		case "unverified", "verified", "invalidated", "archived":
			// valid
		default:
			return fmt.Errorf("invalid status %q (must be unverified, verified, invalidated, or archived)", input.Status)
		}
	}
	return nil
}

// parseInsightMetadata unmarshals raw metadata into a mutable map.
func parseInsightMetadata(raw json.RawMessage) (map[string]any, error) {
	meta := make(map[string]any)
	if len(raw) == 0 {
		return meta, nil
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("parsing insight metadata: %w", err)
	}
	return meta, nil
}

// applyInsightUpdates merges input fields into the metadata map.
func applyInsightUpdates(meta map[string]any, input UpdateInsightInput) {
	if meta == nil {
		return
	}
	if input.Status != "" {
		meta["status"] = input.Status
	}
	if input.AppendEvidence != "" {
		// Write to supporting_evidence (new convention), fallback read from evidence (legacy)
		evidence := metaSlice(meta, "supporting_evidence")
		if evidence == nil {
			evidence = metaSlice(meta, "evidence")
		}
		meta["supporting_evidence"] = append(evidence, input.AppendEvidence)
	}
	if input.AppendCounterEvidence != "" {
		ce := metaSlice(meta, "counter_evidence")
		meta["counter_evidence"] = append(ce, input.AppendCounterEvidence)
	}
	if input.Conclusion != "" {
		meta["conclusion"] = input.Conclusion
	}
}

// metaSlice extracts a []any value from a metadata map key.
func metaSlice(meta map[string]any, key string) []any {
	if ev, ok := meta[key].([]any); ok {
		return ev
	}
	return nil
}

// countEvidence counts supporting_evidence (or legacy evidence) entries in raw metadata.
func countEvidence(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return 0
	}
	if ev, ok := m["supporting_evidence"].([]any); ok {
		return len(ev)
	}
	if ev, ok := m["evidence"].([]any); ok {
		return len(ev)
	}
	return 0
}
