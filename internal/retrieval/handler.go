package retrieval

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	fsrs "github.com/open-spaced-repetition/go-fsrs/v4"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/project"
)

// Handler handles retrieval HTTP requests.
type Handler struct {
	store    *Store
	contents *content.Store
	projects *project.Store
	logger   *slog.Logger
}

// NewHandler returns a retrieval Handler.
func NewHandler(store *Store, contents *content.Store, projects *project.Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, contents: contents, projects: projects, logger: logger}
}

type reviewRequest struct {
	ContentSlug string  `json:"content_slug"`
	Rating      int     `json:"rating"`
	Tag         *string `json:"tag,omitempty"`
}

// ReviewHTTP handles POST /api/admin/retrieval/review.
func (h *Handler) ReviewHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req reviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.ContentSlug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "content_slug is required")
		return
	}
	if req.Rating < 1 || req.Rating > 4 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "rating must be 1-4")
		return
	}

	c, err := h.contents.ContentBySlug(r.Context(), req.ContentSlug)
	if err != nil {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "content not found")
		return
	}

	result, err := h.store.ReviewCard(r.Context(), c.ID, req.Tag, fsrs.Rating(req.Rating), time.Now())
	if err != nil {
		h.logger.Error("reviewing card", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to record review")
		return
	}

	api.Encode(w, http.StatusCreated, api.Response{Data: result})
}

// QueueHTTP handles GET /api/admin/retrieval/queue?project=xxx&limit=10.
func (h *Handler) QueueHTTP(w http.ResponseWriter, r *http.Request) {
	var projectID *uuid.UUID
	if slug := r.URL.Query().Get("project"); slug != "" {
		proj, err := h.projects.ProjectBySlug(r.Context(), slug)
		if err != nil {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
			return
		}
		projectID = &proj.ID
	}

	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			limit = min(n, 50)
		}
	}

	items, err := h.store.Queue(r.Context(), projectID, time.Now(), limit)
	if err != nil {
		h.logger.Error("querying retrieval queue", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query queue")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: QueueResult{Items: items}})
}
