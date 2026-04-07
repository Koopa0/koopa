package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/journal"
)

// --- write_journal ---

// WriteJournalInput is the input for the write_journal tool.
type WriteJournalInput struct {
	Kind     string         `json:"kind" jsonschema:"required" jsonschema_description:"Entry kind: plan, context, reflection, or metrics"`
	Content  string         `json:"content" jsonschema:"required" jsonschema_description:"Journal entry content (markdown)"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema_description:"Per-kind structured metadata. plan: {reasoning}. metrics: {tasks_planned, tasks_completed, adjustments}. context/reflection: freeform."`
}

// WriteJournalOutput is the output of the write_journal tool.
type WriteJournalOutput struct {
	Entry journal.Entry `json:"entry"`
}

func (s *Server) writeJournal(ctx context.Context, _ *sdkmcp.CallToolRequest, input WriteJournalInput) (*sdkmcp.CallToolResult, WriteJournalOutput, error) {
	if input.Content == "" {
		return nil, WriteJournalOutput{}, fmt.Errorf("content is required")
	}

	kind := journal.Kind(input.Kind)
	switch kind {
	case journal.KindPlan, journal.KindContext, journal.KindReflection, journal.KindMetrics:
		// valid
	default:
		return nil, WriteJournalOutput{}, fmt.Errorf("invalid kind %q (valid: plan, context, reflection, metrics)", input.Kind)
	}

	entry, err := s.journal.Create(ctx, &journal.CreateParams{
		Kind:      kind,
		Source:    s.participant,
		Content:   input.Content,
		Metadata:  input.Metadata,
		EntryDate: s.today(),
	})
	if err != nil {
		return nil, WriteJournalOutput{}, fmt.Errorf("creating journal entry: %w", err)
	}

	s.logger.Info("write_journal", "kind", kind, "id", entry.ID)
	return nil, WriteJournalOutput{Entry: *entry}, nil
}
