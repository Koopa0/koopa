package learning

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/google/uuid"
)

// Handler handles learning analytics HTTP requests.
type Handler struct {
	contents *content.Store
	projects *project.Store
	logger   *slog.Logger
}

// NewHandler returns a learning analytics Handler.
func NewHandler(contents *content.Store, projects *project.Store, logger *slog.Logger) *Handler {
	return &Handler{contents: contents, projects: projects, logger: logger}
}

// CoverageMatrixHTTP handles GET /api/admin/stats/coverage-matrix.
// Query params: project (required), days (default 365, max 365).
func (h *Handler) CoverageMatrixHTTP(w http.ResponseWriter, r *http.Request) {
	proj, ok := h.resolveProject(w, r)
	if !ok {
		return
	}

	days := parseIntParam(r, "days", 1, 365, 365)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := h.contents.TagEntries(r.Context(), content.TypeTIL, &proj.ID, since)
	if err != nil {
		h.logger.Error("querying tag entries for coverage matrix", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query tag entries")
		return
	}

	result := CoverageMatrix(entries, days)
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// TagSummaryHTTP handles GET /api/admin/stats/tag-summary.
// Query params: project (required), tag_prefix (optional), days (default 90, max 365).
func (h *Handler) TagSummaryHTTP(w http.ResponseWriter, r *http.Request) {
	proj, ok := h.resolveProject(w, r)
	if !ok {
		return
	}

	days := parseIntParam(r, "days", 1, 365, 90)
	tagPrefix := r.URL.Query().Get("tag_prefix")
	since := time.Now().AddDate(0, 0, -days)

	entries, err := h.contents.TagEntries(r.Context(), content.TypeTIL, &proj.ID, since)
	if err != nil {
		h.logger.Error("querying tag entries for tag summary", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query tag entries")
		return
	}

	result := TagSummary(entries, tagPrefix, days)
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// WeaknessTrendHTTP handles GET /api/admin/stats/weakness-trend.
// Query params: project (required), tag (required), days (default 30, max 180).
func (h *Handler) WeaknessTrendHTTP(w http.ResponseWriter, r *http.Request) {
	proj, ok := h.resolveProject(w, r)
	if !ok {
		return
	}

	tag := r.URL.Query().Get("tag")
	if tag == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "tag query parameter is required")
		return
	}

	days := parseIntParam(r, "days", 1, 180, 30)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := h.contents.RichTagEntries(r.Context(), content.TypeTIL, &proj.ID, since)
	if err != nil {
		h.logger.Error("querying rich tag entries for weakness trend", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query tag entries")
		return
	}

	result := WeaknessTrend(entries, tag, days)
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// TimelineHTTP handles GET /api/admin/stats/learning-timeline.
// Query params: project (optional), days (default 14, max 90).
func (h *Handler) TimelineHTTP(w http.ResponseWriter, r *http.Request) {
	days := parseIntParam(r, "days", 1, 90, 14)
	since := time.Now().AddDate(0, 0, -days)

	var projectID *uuid.UUID
	if slug := r.URL.Query().Get("project"); slug != "" {
		proj, err := h.projects.ProjectBySlug(r.Context(), slug)
		if err != nil {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
			return
		}
		projectID = &proj.ID
	}

	entries, err := h.contents.RichTagEntries(r.Context(), content.TypeTIL, projectID, since)
	if err != nil {
		h.logger.Error("querying rich tag entries for timeline", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query entries")
		return
	}

	result := Timeline(entries, time.Now())
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// resolveProject extracts and resolves the project query param. Returns false if it wrote an error.
func (h *Handler) resolveProject(w http.ResponseWriter, r *http.Request) (*project.Project, bool) {
	slug := r.URL.Query().Get("project")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "project query parameter is required")
		return nil, false
	}

	proj, err := h.projects.ProjectBySlug(r.Context(), slug)
	if err != nil {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	return proj, true
}

// parseIntParam extracts an integer query param with bounds and default.
func parseIntParam(r *http.Request, name string, minVal, maxVal, defaultVal int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minVal {
		return defaultVal
	}
	return min(n, maxVal)
}
