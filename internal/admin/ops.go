package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/mcp/ops"
)

// OpsResponse is the payload for GET /api/admin/ops. It is a metadata
// inventory of every MCP tool the server currently exposes, sourced from
// the internal/mcp/ops catalog.
//
// This endpoint is read-only and does not trigger any MCP dispatch. It
// exists so admin surfaces can render "what tools exist, who can call
// them, and whether they mutate state" without constructing an MCP
// server or hitting a live transport.
type OpsResponse struct {
	Ops         []ops.Meta `json:"ops"`
	Count       int        `json:"count"`
	GeneratedAt string     `json:"generated_at"`
}

// Ops serves the read-only tool metadata catalog. The response is
// generated from a static in-process catalog; no database or MCP
// server is touched.
func (h *Handler) Ops(w http.ResponseWriter, _ *http.Request) {
	all := ops.All()
	api.Encode(w, http.StatusOK, OpsResponse{
		Ops:         all,
		Count:       len(all),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}
