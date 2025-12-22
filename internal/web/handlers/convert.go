package handlers

import (
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/web/component"
	"github.com/koopa0/koopa/internal/web/page"
)

// extractTextContent extracts text content from ai.Part slice.
// Message content is stored as []*ai.Part (Genkit's content representation).
// For display purposes, we concatenate text from Text and Media parts.
// Tool request/response parts are excluded as they contain structured data.
func extractTextContent(parts []*ai.Part) string {
	if len(parts) == 0 {
		return ""
	}

	var b strings.Builder
	for _, part := range parts {
		if part == nil {
			continue
		}
		// Include Text and Media parts (both have user-visible text)
		// Exclude tool requests/responses (structured data, not for display)
		switch part.Kind {
		case ai.PartText, ai.PartMedia:
			b.WriteString(part.Text)
		}
	}
	return b.String()
}

// sessionsToComponent converts session.Session slice to component.Session slice.
func sessionsToComponent(sessions []*session.Session, activeID uuid.UUID) []component.Session {
	result := make([]component.Session, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, component.Session{
			ID:        sess.ID.String(),
			Title:     sess.Title,
			IsCurrent: sess.ID == activeID,
		})
	}
	return result
}

// messagesToPage converts session.Message slice to page.Message slice.
func messagesToPage(messages []*session.Message) []page.Message {
	result := make([]page.Message, 0, len(messages))
	for _, msg := range messages {
		result = append(result, page.Message{
			ID:      msg.ID.String(),
			Content: extractTextContent(msg.Content),
			Role:    msg.Role,
		})
	}
	return result
}
