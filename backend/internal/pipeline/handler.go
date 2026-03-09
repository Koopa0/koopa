package pipeline

import "net/http"

// Handler handles pipeline and webhook HTTP requests.
// All methods return 501 Not Implemented in Phase A.
type Handler struct{}

// NewHandler returns a pipeline Handler.
func NewHandler() *Handler {
	return &Handler{}
}

// Sync handles POST /api/pipeline/sync.
func (h *Handler) Sync(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Collect handles POST /api/pipeline/collect.
func (h *Handler) Collect(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Generate handles POST /api/pipeline/generate.
func (h *Handler) Generate(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Digest handles POST /api/pipeline/digest.
func (h *Handler) Digest(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookObsidian handles POST /api/webhook/obsidian.
func (h *Handler) WebhookObsidian(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookNotion handles POST /api/webhook/notion.
func (h *Handler) WebhookNotion(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// WebhookGithub handles POST /api/webhook/github.
func (h *Handler) WebhookGithub(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
