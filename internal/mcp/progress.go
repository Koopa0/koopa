// Copyright 2026 Koopa. All rights reserved.

// progress.go holds project_progress, the read-only PARA momentum/stalled
// tool. It returns the OWNER's full PARA intelligence — projects behind
// their cadence, goal milestone rollups, and neglected areas — computed
// LIVE from activity_events at read time. Nothing is stored.
//
// Authorization: gated by requireRegisteredCaller, like the other read-only
// tools. It is deliberately NOT caller-scoped (no created_by=caller filter):
// project / goal / area are the single owner's data, so a caller-scope would
// return empty. The caller-scoped pattern is reserved for list_tasks /
// resolve_task, which act on the caller's OWN proposed todos. Any registered
// agent reads the whole owner PARA here.
//
// HUMAN-ACTIVITY-ONLY: progress is measured solely from activity_events rows
// with actor='human'. Agent/system actors never count — a project a cron
// agent touched but the owner did not is, for momentum purposes, untouched.

package mcp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/project"
)

// ProjectProgressInput carries only the caller self-identification — the tool
// takes no other parameters. It always returns the owner's full PARA.
type ProjectProgressInput struct {
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call."`
}

// ProgressProject is one candidate project's momentum line in the response.
// DaysSinceHumanActivity is null when the project has never had human
// activity (LastHumanActivityAt also null); Stalled is computed from the
// cadence, the open-next-action flag, and the human-activity gap.
type ProgressProject struct {
	Slug                 string  `json:"slug"`
	Title                string  `json:"title"`
	GoalID               *string `json:"goal_id"`
	GoalTitle            *string `json:"goal_title"`
	ExpectedCadence      string  `json:"expected_cadence"`
	LastHumanActivityAt  *string `json:"last_human_activity_at"`
	DaysSinceHumanAction *int    `json:"days_since_human_activity"`
	Stalled              bool    `json:"stalled"`
	OpenNextAction       bool    `json:"open_next_action"`
	MilestoneDone        int64   `json:"milestone_done"`
	MilestoneTotal       int64   `json:"milestone_total"`
}

// ProgressGoal is one active goal's rollup: its own milestone progress plus a
// momentum summary of the projects under it (how many of its candidate
// projects are stalled vs. on track).
type ProgressGoal struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	MilestoneDone   int64  `json:"milestone_done"`
	MilestoneTotal  int64  `json:"milestone_total"`
	ProjectsTotal   int    `json:"projects_total"`
	ProjectsStalled int    `json:"projects_stalled"`
}

// ProgressArea is one active area's neglect line.
type ProgressArea struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	AreaNeglected bool   `json:"area_neglected"`
}

// ProjectProgressOutput is the structured project_progress response: the
// owner's candidate projects, active-goal rollups, and active areas.
type ProjectProgressOutput struct {
	Projects []ProgressProject `json:"projects"`
	Goals    []ProgressGoal    `json:"goals"`
	Areas    []ProgressArea    `json:"areas"`
}

func (s *Server) projectProgress(ctx context.Context, _ *mcp.CallToolRequest, in ProjectProgressInput) (*mcp.CallToolResult, ProjectProgressOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "project_progress"); err != nil {
		return nil, ProjectProgressOutput{}, err
	}

	// now is the live instant in the owner's timezone — the reference point
	// for every stalled / neglected comparison, threaded into the pure
	// decision functions so the read is reproducible against a fixed clock.
	now := time.Now().In(s.loc)

	momentum, err := s.projects.Momentum(ctx)
	if err != nil {
		return nil, ProjectProgressOutput{}, err
	}
	goalMilestones, err := s.projects.ActiveGoalMilestones(ctx)
	if err != nil {
		return nil, ProjectProgressOutput{}, err
	}
	areaActivity, err := s.projects.ActiveAreaActivity(ctx)
	if err != nil {
		return nil, ProjectProgressOutput{}, err
	}

	// Per-goal stalled tally, accumulated while shaping the project lines so
	// the goals[] rollup reflects exactly the same stalled decision.
	type goalTally struct {
		total   int
		stalled int
	}
	byGoal := make(map[string]goalTally)

	projects := make([]ProgressProject, len(momentum))
	for i := range momentum {
		m := &momentum[i]
		stalled := project.Stalled(m.LastHumanActivityAt, m.ExpectedCadence, m.OpenNextAction, now)
		projects[i] = ProgressProject{
			Slug:                 m.Slug,
			Title:                m.Title,
			GoalID:               uuidString(m.GoalID),
			GoalTitle:            m.GoalTitle,
			ExpectedCadence:      m.ExpectedCadence,
			LastHumanActivityAt:  rfc3339(m.LastHumanActivityAt),
			DaysSinceHumanAction: project.DaysSince(m.LastHumanActivityAt, now),
			Stalled:              stalled,
			OpenNextAction:       m.OpenNextAction,
			MilestoneDone:        m.MilestoneDone,
			MilestoneTotal:       m.MilestoneTotal,
		}
		if m.GoalID != nil {
			t := byGoal[m.GoalID.String()]
			t.total++
			if stalled {
				t.stalled++
			}
			byGoal[m.GoalID.String()] = t
		}
	}

	goals := make([]ProgressGoal, len(goalMilestones))
	for i := range goalMilestones {
		g := &goalMilestones[i]
		t := byGoal[g.ID.String()]
		goals[i] = ProgressGoal{
			ID:              g.ID.String(),
			Title:           g.Title,
			MilestoneDone:   g.MilestoneDone,
			MilestoneTotal:  g.MilestoneTotal,
			ProjectsTotal:   t.total,
			ProjectsStalled: t.stalled,
		}
	}

	areas := make([]ProgressArea, len(areaActivity))
	for i := range areaActivity {
		a := &areaActivity[i]
		areas[i] = ProgressArea{
			Slug:          a.Slug,
			Name:          a.Name,
			AreaNeglected: project.AreaNeglected(a.LastHumanActivityAt, now),
		}
	}

	return nil, ProjectProgressOutput{
		Projects: projects,
		Goals:    goals,
		Areas:    areas,
	}, nil
}

// rfc3339 renders a nullable instant as an RFC3339 string. nil → nil (JSON
// null) so a project with no human activity reports last_human_activity_at:
// null rather than the zero time.
func rfc3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	return new(t.Format(time.RFC3339))
}

// uuidString renders a nullable UUID as its string form. nil → nil (JSON
// null) so an unlinked project reports goal_id: null rather than a zero UUID.
func uuidString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	return new(id.String())
}
