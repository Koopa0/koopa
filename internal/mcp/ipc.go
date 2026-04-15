package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// file_report and acknowledge_directive are coordination operations from
// the pre-rebuild IPC model. Both handlers are stubbed during the
// coordination rebuild — their real implementation lives in the follow-up
// PR that builds internal/task, internal/message, and internal/artifact.
//
// TODO(coordination-rebuild): rewire file_report → task.Store.Complete
// (attaching an artifact). rewire acknowledge_directive → task.Store.Accept.
// Both should be first-line-guarded by agent.Authorize with
// ActionCompleteTask / ActionAcceptTask respectively.
//
// The tool names stay in the MCP catalog so LLM clients see a stable
// surface; calling either during the rebuild window yields ErrNotImplemented
// so the absence is loud, not silent.

// ErrCoordinationRebuildPending is returned by stubbed coordination tools
// during the rebuild window.
var ErrCoordinationRebuildPending = errors.New(
	"coordination rebuild in progress: this tool returns via the new task/artifact stores in the follow-up PR",
)

// --- file_report ---

// FileReportInput is the input for the file_report tool.
type FileReportInput struct {
	Source           string         `json:"source,omitempty"             jsonschema_description:"Reporting participant (default: calling participant)"`
	InResponseTo     *FlexInt       `json:"in_response_to,omitempty"     jsonschema_description:"Directive ID this report responds to (optional)"`
	Content          string         `json:"content"                      jsonschema:"required" jsonschema_description:"Report content (markdown)"`
	ResolveDirective bool           `json:"resolve_directive,omitempty"  jsonschema_description:"If true and in_response_to is set, marks the directive as resolved with this report as the resolution."`
	Metadata         map[string]any `json:"metadata,omitempty"           jsonschema_description:"Optional metadata"`
}

// FileReportOutput is the output of the file_report tool.
type FileReportOutput struct {
	// Deliberately empty during the rebuild. The post-rebuild shape
	// returns a task.TaskSummary + artifact.ArtifactSummary.
}

func (s *Server) fileReport(_ context.Context, _ *mcp.CallToolRequest, _ FileReportInput) (*mcp.CallToolResult, FileReportOutput, error) {
	return nil, FileReportOutput{}, fmt.Errorf("file_report: %w", ErrCoordinationRebuildPending)
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

func (s *Server) acknowledgeDirective(_ context.Context, _ *mcp.CallToolRequest, _ AcknowledgeDirectiveInput) (*mcp.CallToolResult, AcknowledgeDirectiveOutput, error) {
	return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: %w", ErrCoordinationRebuildPending)
}
