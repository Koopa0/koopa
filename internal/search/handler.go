package search

import (
	"log/slog"
	"net/http"
	"strconv"

	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler serves GET /api/admin/search. Sources are queried in parallel
// under an errgroup — a single failing source logs and degrades that
// slice to empty rather than failing the whole response.
type Handler struct {
	sources []Source
	logger  *slog.Logger
}

// NewHandler returns a search Handler. sources is the ordered list of
// entity kinds the endpoint searches across; pass nil or empty to get a
// handler that always returns zero results (useful in bootstrap).
func NewHandler(sources []Source, logger *slog.Logger) *Handler {
	return &Handler{sources: sources, logger: logger}
}

// Search handles GET /api/admin/search.
// Query params: q (required), limit (optional; default 20, max 50).
// mode=lexical|semantic is accepted but does not branch today; every
// source runs its lexical path.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		api.Encode(w, http.StatusOK, api.Response{Data: Response{Results: []Result{}}})
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"))

	if len(h.sources) == 0 {
		api.Encode(w, http.StatusOK, api.Response{Data: Response{Results: []Result{}}})
		return
	}
	per := LimitPerSource(limit, len(h.sources))

	ctx := r.Context()
	all := make([][]Result, len(h.sources))

	g, gctx := errgroup.WithContext(ctx)
	for i, src := range h.sources {
		g.Go(func() error {
			hits, err := src.Search(gctx, query, per)
			if err != nil {
				h.logger.Warn("search: source failed",
					"kind", src.Kind(),
					"error", err)
				all[i] = nil
				return nil
			}
			all[i] = hits
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		h.logger.Error("search: source group failed", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "search failed")
		return
	}

	merged := make([]Result, 0, limit)
	for _, hits := range all {
		merged = append(merged, hits...)
	}
	if len(merged) > limit {
		merged = merged[:limit]
	}
	api.Encode(w, http.StatusOK, api.Response{Data: Response{Results: merged}})
}

// parseLimit clamps the client-supplied limit into [1, maxLimit] and
// defaults to 20 when the value is missing or non-numeric.
func parseLimit(raw string) int {
	if raw == "" {
		return 20
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 20
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}
