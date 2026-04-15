package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa0.dev/internal/agent/note"
)

// --- write_journal ---
//
// The MCP tool name stays write_journal for backwards compatibility with
// existing Cowork project instructions. Internally it writes to the
// agent_notes table via internal/agentnote. The "metrics" kind has been
// dropped (no current writer) — only plan / context / reflection are accepted.

// WriteJournalInput is the input for the write_journal tool.
type WriteJournalInput struct {
	Kind     string         `json:"kind" jsonschema:"required" jsonschema_description:"Entry kind: plan, context, or reflection"`
	Content  string         `json:"content" jsonschema:"required" jsonschema_description:"Journal entry content (markdown)"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema_description:"Per-kind structured metadata. plan: {reasoning}. context/reflection: freeform."`
}

// WriteJournalOutput is the output of the write_journal tool.
type WriteJournalOutput struct {
	Entry agentnote.Note `json:"entry"`
}

func (s *Server) writeJournal(ctx context.Context, _ *mcp.CallToolRequest, input WriteJournalInput) (*mcp.CallToolResult, WriteJournalOutput, error) {
	if input.Content == "" {
		return nil, WriteJournalOutput{}, fmt.Errorf("content is required")
	}

	kind := agentnote.Kind(input.Kind)
	switch kind {
	case agentnote.KindPlan, agentnote.KindContext, agentnote.KindReflection:
		// valid
	default:
		return nil, WriteJournalOutput{}, fmt.Errorf("invalid kind %q (valid: plan, context, reflection)", input.Kind)
	}

	entry, err := s.agentNotes.Create(ctx, &agentnote.CreateParams{
		Kind:      kind,
		Author:    s.callerIdentity(ctx),
		Content:   input.Content,
		Metadata:  input.Metadata,
		EntryDate: s.today(),
	})
	if err != nil {
		return nil, WriteJournalOutput{}, fmt.Errorf("creating agent note: %w", err)
	}

	s.logger.Info("write_journal", "kind", kind, "id", entry.ID)
	return nil, WriteJournalOutput{Entry: *entry}, nil
}
