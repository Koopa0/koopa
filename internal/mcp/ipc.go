package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/report"
)

// --- file_report ---

// FileReportInput is the input for the file_report tool.
type FileReportInput struct {
	Source       string         `json:"source,omitempty" jsonschema_description:"Reporting participant (default: calling participant)"`
	InResponseTo *FlexInt       `json:"in_response_to,omitempty" jsonschema_description:"Directive ID this report responds to (optional)"`
	Content      string         `json:"content" jsonschema:"required" jsonschema_description:"Report content (markdown)"`
	Metadata     map[string]any `json:"metadata,omitempty" jsonschema_description:"Optional metadata (follow_up_needed, artifacts, etc)"`
}

// FileReportOutput is the output of the file_report tool.
type FileReportOutput struct {
	Report report.Report `json:"report"`
}

func (s *Server) fileReport(ctx context.Context, _ *mcp.CallToolRequest, input FileReportInput) (*mcp.CallToolResult, FileReportOutput, error) {
	if input.Content == "" {
		return nil, FileReportOutput{}, fmt.Errorf("content is required")
	}

	source := input.Source
	if source == "" {
		source = s.callerIdentity(ctx)
	}

	// Validate source can write reports (reuse directive store's participant query).
	if p, pErr := s.directives.ParticipantByName(ctx, source); pErr != nil {
		return nil, FileReportOutput{}, fmt.Errorf("participant %q not found: %w", source, pErr)
	} else if !p.CanWriteReports {
		return nil, FileReportOutput{}, fmt.Errorf("participant %q does not have can_write_reports capability", source)
	}

	var inResponseTo *int64
	if input.InResponseTo != nil {
		v := int64(*input.InResponseTo)
		inResponseTo = &v
	}

	var metadata json.RawMessage
	if input.Metadata != nil {
		metadata, _ = json.Marshal(input.Metadata)
	}

	rpt, err := s.reports.Create(ctx, &report.CreateParams{
		Source:       source,
		InResponseTo: inResponseTo,
		Content:      input.Content,
		Metadata:     metadata,
		ReportedDate: s.today(),
	})
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("filing report: %w", err)
	}

	s.logger.Info("file_report", "id", rpt.ID, "source", source, "in_response_to", inResponseTo)
	return nil, FileReportOutput{Report: *rpt}, nil
}

// --- acknowledge_directive ---

// AcknowledgeDirectiveInput is the input for the acknowledge_directive tool.
type AcknowledgeDirectiveInput struct {
	DirectiveID FlexInt `json:"directive_id" jsonschema:"required" jsonschema_description:"Directive ID to acknowledge"`
}

// AcknowledgeDirectiveOutput is the output of the acknowledge_directive tool.
type AcknowledgeDirectiveOutput struct {
	DirectiveID    int64  `json:"directive_id"`
	AcknowledgedBy string `json:"acknowledged_by"`
	Acknowledged   bool   `json:"acknowledged"`
}

func (s *Server) acknowledgeDirective(ctx context.Context, _ *mcp.CallToolRequest, input AcknowledgeDirectiveInput) (*mcp.CallToolResult, AcknowledgeDirectiveOutput, error) {
	id := int64(input.DirectiveID)
	if id <= 0 {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("valid directive_id is required")
	}

	d, err := s.directives.Acknowledge(ctx, id, s.callerIdentity(ctx))
	if err != nil {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledging directive: %w", err)
	}

	s.logger.Info("acknowledge_directive", "id", d.ID, "by", s.callerIdentity(ctx))
	return nil, AcknowledgeDirectiveOutput{
		DirectiveID:    d.ID,
		AcknowledgedBy: s.callerIdentity(ctx),
		Acknowledged:   true,
	}, nil
}
