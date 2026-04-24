package agent

import (
	"log/slog"
	"net/http"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler handles agent HTTP requests for the admin workbench.
type Handler struct {
	registry *Registry
	logger   *slog.Logger
}

// NewHandler returns an agent Handler.
func NewHandler(registry *Registry, logger *slog.Logger) *Handler {
	return &Handler{registry: registry, logger: logger}
}

// agentResponse is the JSON-serializable agent shape for the API.
type agentResponse struct {
	Name        Name   `json:"name"`
	DisplayName string `json:"display_name"`
	Platform    string `json:"platform"`
	Description string `json:"description"`
	Capability  struct {
		SubmitTasks      bool `json:"submit_tasks"`
		ReceiveTasks     bool `json:"receive_tasks"`
		PublishArtifacts bool `json:"publish_artifacts"`
	} `json:"capability"`
	Schedule *scheduleResponse `json:"schedule,omitempty"`
	Status   Status            `json:"status"`
}

type scheduleResponse struct {
	Name    string      `json:"name"`
	Trigger TriggerKind `json:"trigger"`
	Expr    string      `json:"expr"`
	Backend string      `json:"backend"`
	Purpose string      `json:"purpose"`
}

func toAgentResponse(a *Agent) agentResponse {
	resp := agentResponse{
		Name:        a.Name,
		DisplayName: a.DisplayName,
		Platform:    a.Platform,
		Description: a.Description,
		Status:      a.Status,
	}
	resp.Capability.SubmitTasks = a.Capability.SubmitTasks
	resp.Capability.ReceiveTasks = a.Capability.ReceiveTasks
	resp.Capability.PublishArtifacts = a.Capability.PublishArtifacts
	if !a.Schedule.IsZero() {
		resp.Schedule = &scheduleResponse{
			Name:    a.Schedule.Name,
			Trigger: a.Schedule.Trigger,
			Expr:    a.Schedule.Expr,
			Backend: a.Schedule.Backend,
			Purpose: a.Schedule.Purpose,
		}
	}
	return resp
}

// List handles GET /api/admin/agents.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	agents := h.registry.All()
	result := make([]agentResponse, len(agents))
	for i := range agents {
		result[i] = toAgentResponse(&agents[i])
	}
	api.Encode(w, http.StatusOK, api.Response{Data: result})
}

// Get handles GET /api/admin/agents/{name}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	name := Name(r.PathValue("name"))
	a, err := h.registry.Get(name)
	if err != nil {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "agent not found")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: toAgentResponse(&a)})
}
