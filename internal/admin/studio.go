package admin

import (
	"net/http"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// TODO(coordination-rebuild): rebuild studio overview against the new
// coordination entities.
//
// The original file read from directive.Store + report.Store and surfaced a
// per-participant capability board (CanIssueDirectives, CanReceiveDirectives,
// CanWriteReports, TaskAssignable, HasSchedule). Both stores have been
// deleted in the coordination rebuild and the capability flags no longer
// live in the database — they live on agent.Capability in the Go registry.
//
// The replacement should:
//   - read open tasks from task.Store.Summarize (when task package exists
//     in the next stage of the rebuild)
//   - read recent artifacts from artifact.Store (when artifact package exists)
//   - fan out agent.Registry.All() for the participant listing, deriving
//     active_tasks / recent_artifacts counts via the same stores
//   - derive capability bits from agent.Agent.Capability (not DB columns)
//
// Until the task/message/artifact packages exist, this handler returns an
// empty shell so the admin UI has a stable contract it can dispatch on
// ("no data yet" vs "endpoint removed").

type studioOverviewResponse struct {
	OpenTasks       []any `json:"open_tasks"`
	ResolvedTasks   []any `json:"resolved_tasks,omitempty"`
	RecentArtifacts []any `json:"recent_artifacts"`
	Agents          []any `json:"agents"`
	Stats           struct {
		UnackedCount    int `json:"unacked_count"`
		InProgressCount int `json:"in_progress_count"`
	} `json:"stats"`
}

// StudioOverview handles GET /api/admin/studio/overview.
//
// Returns an empty shell until the coordination rebuild wires the new task /
// artifact stores. Frontend should interpret empty arrays as "no data yet",
// not "endpoint gone".
func (h *Handler) StudioOverview(w http.ResponseWriter, _ *http.Request) {
	out := studioOverviewResponse{
		OpenTasks:       []any{},
		RecentArtifacts: []any{},
		Agents:          []any{},
	}
	api.Encode(w, http.StatusOK, out)
}
