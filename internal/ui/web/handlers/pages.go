package handlers

import (
	"log/slog"
	"net/http"

	"github.com/koopa0/koopa-cli/internal/ui/web/page"
)

// Pages handles page rendering requests.
type Pages struct {
	logger *slog.Logger
}

// NewPages creates a new Pages handler.
func NewPages(logger *slog.Logger) *Pages {
	return &Pages{logger: logger}
}

// Chat renders the main chat page.
func (h *Pages) Chat(w http.ResponseWriter, r *http.Request) {
	// TODO: Get session ID from cookie or create new session
	sessionID := "default"

	// TODO: Get CSRF token from session
	csrfToken := ""

	props := page.ChatPageProps{
		SessionID: sessionID,
		CSRFToken: csrfToken,
	}

	if err := page.Chat(props).Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render chat page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
