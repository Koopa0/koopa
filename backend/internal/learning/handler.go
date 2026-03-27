package learning

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
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

	entries, err := h.contents.TagEntries(r.Context(), content.TypeTIL, &proj.ID, since)
	if err != nil {
		h.logger.Error("querying tag entries for weakness trend", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query tag entries")
		return
	}

	result := WeaknessTrend(entries, tag, days)
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
