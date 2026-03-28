package mcp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
)

// --- buildProjectsByGoalID ---

func TestBuildProjectsByGoalID(t *testing.T) {
	t.Parallel()

	goalA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	goalB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	tests := []struct {
		name     string
		projects []project.Project
		want     map[uuid.UUID][]string
	}{
		{
			name:     "empty projects returns empty map",
			projects: []project.Project{},
			want:     map[uuid.UUID][]string{},
		},
		{
			name: "single project with goal ID",
			projects: []project.Project{
				{Title: "Blog Redesign", GoalID: &goalA},
			},
			want: map[uuid.UUID][]string{
				goalA: {"Blog Redesign"},
			},
		},
		{
			name: "multiple projects under same goal",
			projects: []project.Project{
				{Title: "Project Alpha", GoalID: &goalA},
				{Title: "Project Beta", GoalID: &goalA},
			},
			want: map[uuid.UUID][]string{
				goalA: {"Project Alpha", "Project Beta"},
			},
		},
		{
			name: "projects under different goals",
			projects: []project.Project{
				{Title: "Project Alpha", GoalID: &goalA},
				{Title: "Project Gamma", GoalID: &goalB},
			},
			want: map[uuid.UUID][]string{
				goalA: {"Project Alpha"},
				goalB: {"Project Gamma"},
			},
		},
		{
			name: "project with nil goal ID is excluded",
			projects: []project.Project{
				{Title: "Orphan Project", GoalID: nil},
				{Title: "Linked Project", GoalID: &goalA},
			},
			want: map[uuid.UUID][]string{
				goalA: {"Linked Project"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildProjectsByGoalID(tt.projects)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildProjectsByGoalID() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- buildCompletionsByProject ---

func TestBuildCompletionsByProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		byProject []activity.ProjectCompletion
		want      map[string]int64
	}{
		{
			name:      "empty input returns empty map",
			byProject: []activity.ProjectCompletion{},
			want:      map[string]int64{},
		},
		{
			name: "single project",
			byProject: []activity.ProjectCompletion{
				{ProjectTitle: "Blog", Completed: 5},
			},
			want: map[string]int64{
				"Blog": 5,
			},
		},
		{
			name: "multiple distinct projects",
			byProject: []activity.ProjectCompletion{
				{ProjectTitle: "Blog", Completed: 5},
				{ProjectTitle: "API", Completed: 12},
				{ProjectTitle: "Docs", Completed: 3},
			},
			want: map[string]int64{
				"Blog": 5,
				"API":  12,
				"Docs": 3,
			},
		},
		{
			name: "zero completions entry included",
			byProject: []activity.ProjectCompletion{
				{ProjectTitle: "Idle", Completed: 0},
			},
			want: map[string]int64{
				"Idle": 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildCompletionsByProject(tt.byProject)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildCompletionsByProject() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- buildWeeklyGoal ---

func TestBuildWeeklyGoal(t *testing.T) {
	t.Parallel()

	goalID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	today := time.Date(2025, 3, 28, 0, 0, 0, 0, time.UTC)
	deadline := today.AddDate(0, 0, 30) // 30 days out — on_track if tasks done

	tests := []struct {
		name                 string
		g                    *goal.Goal
		projectsByGoalID     map[uuid.UUID][]string
		completionsByProject map[string]int64
		today                time.Time
		wantTitle            string
		wantOnTrack          string
		wantRelatedCount     int
		wantTasksCompleted   int64
		wantDeadline         string
	}{
		{
			name: "goal with related projects and completions is on_track",
			g: &goal.Goal{
				ID:       goalID,
				Title:    "Ship v2",
				Status:   goal.StatusInProgress,
				Deadline: &deadline,
			},
			projectsByGoalID:     map[uuid.UUID][]string{goalID: {"Blog", "API"}},
			completionsByProject: map[string]int64{"Blog": 4, "API": 6},
			today:                today,
			wantTitle:            "Ship v2",
			wantOnTrack:          "on_track",
			wantRelatedCount:     2,
			wantTasksCompleted:   10,
			wantDeadline:         "2025-04-27",
		},
		{
			name: "goal without related projects — empty slice, off_track",
			g: &goal.Goal{
				ID:       goalID,
				Title:    "Learn Go",
				Status:   goal.StatusInProgress,
				Deadline: &deadline,
			},
			projectsByGoalID:     map[uuid.UUID][]string{},
			completionsByProject: map[string]int64{},
			today:                today,
			wantTitle:            "Learn Go",
			wantOnTrack:          "off_track",
			wantRelatedCount:     0,
			wantTasksCompleted:   0,
			wantDeadline:         "2025-04-27",
		},
		{
			name: "goal with no deadline",
			g: &goal.Goal{
				ID:       goalID,
				Title:    "Open Source",
				Status:   goal.StatusNotStarted,
				Deadline: nil,
			},
			projectsByGoalID:     map[uuid.UUID][]string{goalID: {"OSS Project"}},
			completionsByProject: map[string]int64{"OSS Project": 0},
			today:                today,
			wantTitle:            "Open Source",
			wantOnTrack:          "at_risk", // zero completions, no deadline → at_risk
			wantRelatedCount:     1,
			wantTasksCompleted:   0,
			wantDeadline:         "",
		},
		{
			name: "goal with completions but no deadline — on_track",
			g: &goal.Goal{
				ID:       goalID,
				Title:    "Ongoing Work",
				Status:   goal.StatusInProgress,
				Deadline: nil,
			},
			projectsByGoalID:     map[uuid.UUID][]string{goalID: {"Main"}},
			completionsByProject: map[string]int64{"Main": 3},
			today:                today,
			wantTitle:            "Ongoing Work",
			wantOnTrack:          "on_track",
			wantRelatedCount:     1,
			wantTasksCompleted:   3,
			wantDeadline:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildWeeklyGoal(tt.g, tt.projectsByGoalID, tt.completionsByProject, tt.today)

			if diff := cmp.Diff(tt.wantTitle, got.Title); diff != "" {
				t.Errorf("Title mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantOnTrack, got.OnTrack); diff != "" {
				t.Errorf("OnTrack mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantTasksCompleted, got.RelatedTasksCompleted); diff != "" {
				t.Errorf("RelatedTasksCompleted mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantRelatedCount, len(got.RelatedProjects)); diff != "" {
				t.Errorf("len(RelatedProjects) mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantDeadline, got.Deadline); diff != "" {
				t.Errorf("Deadline mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
