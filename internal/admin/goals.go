package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/goal"
)

// GoalsOverviewResponse is the payload for GET /api/admin/plan/goals.
type GoalsOverviewResponse struct {
	ByArea []AreaGoalGroup `json:"by_area"`
}

// AreaGoalGroup groups goals by area.
type AreaGoalGroup struct {
	AreaID   string        `json:"area_id"`
	AreaName string        `json:"area_name"`
	AreaSlug string        `json:"area_slug"`
	Goals    []GoalSummary `json:"goals"`
}

// GoalSummary is a goal with milestone progress for list views.
type GoalSummary struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Status          string `json:"status"`
	Deadline        string `json:"deadline,omitempty"`
	DaysRemaining   *int   `json:"days_remaining,omitempty"`
	MilestonesTotal int    `json:"milestones_total"`
	MilestonesDone  int    `json:"milestones_done"`
	NextMilestone   string `json:"next_milestone,omitempty"`
	ProjectsCount   int    `json:"projects_count"`
	Quarter         string `json:"quarter,omitempty"`
}

// GoalsOverview handles GET /api/admin/plan/goals.
func (h *Handler) GoalsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	goals, err := h.goals.ActiveGoals(ctx)
	if err != nil {
		h.logger.Error("goals overview", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	// Batch fetch project counts per goal.
	goalIDs := make([]uuid.UUID, len(goals))
	for i := range goals {
		goalIDs[i] = goals[i].ID
	}
	projSummaries, _ := h.projects.SummariesByGoalIDs(ctx, goalIDs)
	projCounts := map[uuid.UUID]int{}
	for i := range projSummaries {
		if projSummaries[i].GoalID != nil {
			projCounts[*projSummaries[i].GoalID]++
		}
	}

	// Group by area.
	areaMap := map[string]*AreaGoalGroup{}
	var areaOrder []string

	for i := range goals {
		g := &goals[i]
		areaKey := g.AreaName
		if areaKey == "" {
			areaKey = "unassigned"
		}
		group, ok := areaMap[areaKey]
		if !ok {
			group = &AreaGoalGroup{
				AreaName: areaKey,
				Goals:    []GoalSummary{},
			}
			areaMap[areaKey] = group
			areaOrder = append(areaOrder, areaKey)
		}

		gs := GoalSummary{
			ID:              g.ID.String(),
			Title:           g.Title,
			Status:          string(g.Status),
			MilestonesTotal: int(g.MilestoneTotal),
			MilestonesDone:  int(g.MilestoneDone),
			ProjectsCount:   projCounts[g.ID],
		}
		if g.Quarter != nil {
			gs.Quarter = *g.Quarter
		}
		if g.Deadline != nil {
			gs.Deadline = g.Deadline.Format(time.DateOnly)
			days := int(time.Until(*g.Deadline).Hours() / 24)
			gs.DaysRemaining = &days
		}
		group.Goals = append(group.Goals, gs)
	}

	result := make([]AreaGoalGroup, 0, len(areaOrder))
	for _, key := range areaOrder {
		result = append(result, *areaMap[key])
	}

	api.Encode(w, http.StatusOK, GoalsOverviewResponse{ByArea: result})
}

// GoalDetailResponse is the payload for GET /api/admin/plan/goals/{id}.
type GoalDetailResponse struct {
	ID             string             `json:"id"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	Status         string             `json:"status"`
	AreaName       string             `json:"area_name,omitempty"`
	Deadline       string             `json:"deadline,omitempty"`
	Quarter        string             `json:"quarter,omitempty"`
	CreatedAt      string             `json:"created_at"`
	Health         string             `json:"health"`
	Milestones     []MilestoneSummary `json:"milestones"`
	Projects       []ProjectBrief     `json:"projects"`
	RecentActivity []GoalActivityItem `json:"recent_activity"`
}

// GoalActivityItem is one entry in a goal's recent activity timeline.
// type is a typed enum: milestone_completed | task_completed | content_published.
type GoalActivityItem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	RefID     string `json:"ref_id"`
	RefSlug   string `json:"ref_slug,omitempty"`
	Timestamp string `json:"timestamp"`
}

// MilestoneSummary is a milestone for goal detail.
type MilestoneSummary struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Completed   bool   `json:"completed"`
	CompletedAt string `json:"completed_at,omitempty"`
	Position    int    `json:"position"`
}

// ProjectBrief is a lightweight project view for goal detail.
type ProjectBrief struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// GoalDetail handles GET /api/admin/plan/goals/{id}.
func (h *Handler) GoalDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	goalID, err := uuid.Parse(idStr)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}

	ctx := r.Context()

	g, err := h.goals.ByID(ctx, goalID)
	if errors.Is(err, goal.ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "goal not found")
		return
	}
	if err != nil {
		h.logger.Error("goal detail", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	resp := GoalDetailResponse{
		ID:          g.ID.String(),
		Title:       g.Title,
		Description: g.Description,
		Status:      string(g.Status),
		CreatedAt:   g.CreatedAt.Format(time.RFC3339),
		Health:      "on-track",
	}
	if g.AreaName != "" {
		resp.AreaName = g.AreaName
	}
	if g.Deadline != nil {
		resp.Deadline = g.Deadline.Format(time.DateOnly)
	}
	if g.Quarter != nil {
		resp.Quarter = *g.Quarter
	}

	// Milestones.
	milestones, _ := h.goals.MilestonesByGoal(ctx, goalID)
	resp.Milestones = make([]MilestoneSummary, len(milestones))
	for i := range milestones {
		ms := &milestones[i]
		resp.Milestones[i] = MilestoneSummary{
			ID:        ms.ID.String(),
			Title:     ms.Title,
			Completed: ms.CompletedAt != nil,
			Position:  int(ms.Position),
		}
		if ms.CompletedAt != nil {
			resp.Milestones[i].CompletedAt = ms.CompletedAt.Format(time.RFC3339)
		}
	}

	// Projects linked to this goal.
	projSummaries, _ := h.projects.SummariesByGoalIDs(ctx, []uuid.UUID{goalID})
	resp.Projects = make([]ProjectBrief, len(projSummaries))
	for i := range projSummaries {
		resp.Projects[i] = ProjectBrief{
			ID:     projSummaries[i].ID.String(),
			Title:  projSummaries[i].Title,
			Status: string(projSummaries[i].Status),
		}
	}

	// Recent activity (UNION across milestones, tasks, contents).
	resp.RecentActivity = []GoalActivityItem{}
	activity, aErr := h.goals.RecentActivity(ctx, goalID, 10)
	if aErr != nil {
		h.logger.Warn("goal recent activity", "goal_id", goalID, "error", aErr)
	}
	for i := range activity {
		a := &activity[i]
		item := GoalActivityItem{
			Type:      string(a.Type),
			Title:     a.Title,
			RefID:     a.RefID,
			Timestamp: a.Timestamp.Format(time.RFC3339),
		}
		if a.RefSlug != nil {
			item.RefSlug = *a.RefSlug
		}
		resp.RecentActivity = append(resp.RecentActivity, item)
	}

	api.Encode(w, http.StatusOK, resp)
}

// GoalProposeRequest is the request body for POST /api/admin/plan/goals/propose.
type GoalProposeRequest struct {
	Title       string  `json:"title"`
	Description string  `json:"description"`
	AreaID      *string `json:"area_id"`
	Deadline    *string `json:"deadline"`
	Quarter     *string `json:"quarter"`
}

// GoalPropose handles POST /api/admin/plan/goals/propose.
func (h *Handler) GoalPropose(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[GoalProposeRequest](w, r)
	if err != nil {
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}

	// Build preview.
	preview := map[string]any{
		"title":       req.Title,
		"description": req.Description,
	}
	if req.Deadline != nil {
		preview["deadline"] = *req.Deadline
	}
	if req.Quarter != nil {
		preview["quarter"] = *req.Quarter
	}

	// Count existing goals in the same area for context.
	ctx := r.Context()
	existingCount := 0
	if req.AreaID != nil {
		if goals, err := h.goals.ActiveGoals(ctx); err == nil {
			for i := range goals {
				if goals[i].AreaID != nil && goals[i].AreaID.String() == *req.AreaID {
					existingCount++
				}
			}
		}
	}
	preview["existing_goals_in_area"] = existingCount

	// Store proposal in-memory (stateless HMAC approach matches MCP pattern,
	// but for HTTP API we use a simpler server-side temp store).
	proposalID := uuid.New().String()
	h.storeProposal(proposalID, "goal", req)

	api.Encode(w, http.StatusOK, map[string]any{
		"proposal_id": proposalID,
		"preview":     preview,
	})
}

// GoalCommit handles POST /api/admin/plan/goals/propose/{proposal_id}/commit.
func (h *Handler) GoalCommit(w http.ResponseWriter, r *http.Request) {
	proposalID := r.PathValue("proposal_id")
	data, ok := h.loadProposal(proposalID)
	if !ok {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "proposal not found or expired")
		return
	}

	req, ok := data.(GoalProposeRequest)
	if !ok {
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "invalid proposal data")
		return
	}

	var deadline *time.Time
	if req.Deadline != nil {
		d, err := time.Parse(time.DateOnly, *req.Deadline)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid deadline")
			return
		}
		deadline = &d
	}

	var areaID *uuid.UUID
	if req.AreaID != nil {
		id, err := uuid.Parse(*req.AreaID)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid area_id")
			return
		}
		areaID = &id
	}

	g, err := h.goals.Create(r.Context(), &goal.CreateParams{
		Title:       req.Title,
		Description: req.Description,
		AreaID:      areaID,
		Deadline:    deadline,
		Quarter:     req.Quarter,
	})
	if err != nil {
		h.logger.Error("goal commit", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusCreated, map[string]any{
		"id":    g.ID.String(),
		"title": g.Title,
	})
}

// MilestoneCreateRequest is the request body for POST /api/admin/plan/goals/{id}/milestones.
type MilestoneCreateRequest struct {
	Title    string `json:"title"`
	Position *int   `json:"position"`
}

// MilestoneCreate handles POST /api/admin/plan/goals/{id}/milestones.
func (h *Handler) MilestoneCreate(w http.ResponseWriter, r *http.Request) {
	goalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid goal id")
		return
	}

	req, err := api.Decode[MilestoneCreateRequest](w, r)
	if err != nil {
		return
	}
	if req.Title == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "title is required")
		return
	}

	pos := int32(0)
	if req.Position != nil {
		pos = int32(*req.Position) //nolint:gosec // G115: position is small, bounded by UI
	}

	ms, err := h.goals.CreateMilestoneSimple(r.Context(), goalID, req.Title, pos)
	if err != nil {
		h.logger.Error("milestone create", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusCreated, ms)
}

// MilestoneToggle handles POST /api/admin/plan/goals/{id}/milestones/{ms_id}/toggle.
func (h *Handler) MilestoneToggle(w http.ResponseWriter, r *http.Request) {
	msID, err := uuid.Parse(r.PathValue("ms_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid milestone id")
		return
	}

	ms, err := h.goals.ToggleMilestone(r.Context(), msID)
	if err != nil {
		h.logger.Error("milestone toggle", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusOK, ms)
}
