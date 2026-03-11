// Package reconcile compares Obsidian files and Notion records against local database state.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sync/errgroup"
)

// DirectoryLister lists markdown file slugs in a directory.
type DirectoryLister interface {
	ListDirectory(ctx context.Context, path string) ([]string, error)
}

// ObsidianSlugLister lists all content slugs sourced from Obsidian.
type ObsidianSlugLister interface {
	ObsidianContentSlugs(ctx context.Context) ([]string, error)
}

// NotionPageIDLister lists all synced Notion page IDs.
type NotionPageIDLister interface {
	NotionPageIDs(ctx context.Context) ([]string, error)
}

// NotionDBQuerier queries a Notion database and returns page IDs.
type NotionDBQuerier interface {
	QueryPageIDs(ctx context.Context, databaseID string) ([]string, error)
}

// Sender sends a text notification.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// Report holds the reconciliation results.
type Report struct {
	// Obsidian: files in GitHub but not in local DB
	ObsidianMissing []string
	// Obsidian: records in local DB but not in GitHub
	ObsidianOrphaned []string
	// Projects: in Notion but not in local DB
	ProjectsMissing []string
	// Projects: in local DB but not in Notion
	ProjectsOrphaned []string
	// Goals: in Notion but not in local DB
	GoalsMissing []string
	// Goals: in local DB but not in Notion
	GoalsOrphaned []string
}

// HasIssues reports whether the reconciliation found any discrepancies.
func (r Report) HasIssues() bool {
	return len(r.ObsidianMissing) > 0 || len(r.ObsidianOrphaned) > 0 ||
		len(r.ProjectsMissing) > 0 || len(r.ProjectsOrphaned) > 0 ||
		len(r.GoalsMissing) > 0 || len(r.GoalsOrphaned) > 0
}

// Config holds the configuration for reconciliation.
type Config struct {
	NotionProjectsDB string
	NotionGoalsDB    string
}

// Reconciler runs weekly reconciliation checks.
type Reconciler struct {
	github   DirectoryLister
	content  ObsidianSlugLister
	projects NotionPageIDLister
	goals    NotionPageIDLister
	notion   NotionDBQuerier
	notifier Sender
	config   Config
	logger   *slog.Logger
}

// New returns a Reconciler.
func New(
	github DirectoryLister,
	content ObsidianSlugLister,
	projects NotionPageIDLister,
	goals NotionPageIDLister,
	notion NotionDBQuerier,
	notifier Sender,
	cfg Config,
	logger *slog.Logger,
) *Reconciler {
	return &Reconciler{
		github:   github,
		content:  content,
		projects: projects,
		goals:    goals,
		notion:   notion,
		notifier: notifier,
		config:   cfg,
		logger:   logger,
	}
}

// Run executes the reconciliation and sends a report if issues are found.
func (r *Reconciler) Run(ctx context.Context) error {
	r.logger.Info("reconciliation starting")

	var (
		githubSlugs   []string
		githubErr     error
		localSlugs    []string
		localErr      error
		localProjIDs  []string
		localProjErr  error
		notionProjIDs []string
		notionProjErr error
		localGoalIDs  []string
		localGoalErr  error
		notionGoalIDs []string
		notionGoalErr error
	)

	g := new(errgroup.Group)

	// Obsidian: GitHub vs local
	g.Go(func() error {
		githubSlugs, githubErr = r.github.ListDirectory(ctx, "10-Public-Content")
		return nil
	})
	g.Go(func() error {
		localSlugs, localErr = r.content.ObsidianContentSlugs(ctx)
		return nil
	})

	// Projects: Notion vs local
	g.Go(func() error {
		localProjIDs, localProjErr = r.projects.NotionPageIDs(ctx)
		return nil
	})
	g.Go(func() error {
		if r.config.NotionProjectsDB == "" {
			return nil
		}
		notionProjIDs, notionProjErr = r.notion.QueryPageIDs(ctx, r.config.NotionProjectsDB)
		return nil
	})

	// Goals: Notion vs local
	g.Go(func() error {
		localGoalIDs, localGoalErr = r.goals.NotionPageIDs(ctx)
		return nil
	})
	g.Go(func() error {
		if r.config.NotionGoalsDB == "" {
			return nil
		}
		notionGoalIDs, notionGoalErr = r.notion.QueryPageIDs(ctx, r.config.NotionGoalsDB)
		return nil
	})

	_ = g.Wait()

	report := Report{}

	// Obsidian comparison
	switch {
	case githubErr != nil:
		r.logger.Error("reconcile: listing github directory", "error", githubErr)
	case localErr != nil:
		r.logger.Error("reconcile: listing obsidian content", "error", localErr)
	default:
		report.ObsidianMissing, report.ObsidianOrphaned = diff(githubSlugs, localSlugs)
	}

	// Projects comparison
	switch {
	case localProjErr != nil:
		r.logger.Error("reconcile: listing local project page ids", "error", localProjErr)
	case notionProjErr != nil:
		r.logger.Error("reconcile: querying notion projects", "error", notionProjErr)
	case len(notionProjIDs) > 0:
		report.ProjectsMissing, report.ProjectsOrphaned = diff(notionProjIDs, localProjIDs)
	}

	// Goals comparison
	switch {
	case localGoalErr != nil:
		r.logger.Error("reconcile: listing local goal page ids", "error", localGoalErr)
	case notionGoalErr != nil:
		r.logger.Error("reconcile: querying notion goals", "error", notionGoalErr)
	case len(notionGoalIDs) > 0:
		report.GoalsMissing, report.GoalsOrphaned = diff(notionGoalIDs, localGoalIDs)
	}

	if !report.HasIssues() {
		r.logger.Info("reconciliation complete, no issues found")
		return nil
	}

	text := formatReport(report)
	r.logger.Warn("reconciliation found issues", "report", text)

	if err := r.notifier.Send(ctx, text); err != nil {
		r.logger.Error("sending reconciliation report", "error", err)
		return fmt.Errorf("sending reconciliation report: %w", err)
	}

	return nil
}

// diff returns items in source but not in target (missing), and items in target but not in source (orphaned).
func diff(source, target []string) (missing, orphaned []string) {
	sourceSet := make(map[string]bool, len(source))
	for _, s := range source {
		sourceSet[s] = true
	}
	targetSet := make(map[string]bool, len(target))
	for _, t := range target {
		targetSet[t] = true
	}

	for _, s := range source {
		if !targetSet[s] {
			missing = append(missing, s)
		}
	}
	for _, t := range target {
		if !sourceSet[t] {
			orphaned = append(orphaned, t)
		}
	}
	return missing, orphaned
}

func formatReport(r Report) string {
	var b strings.Builder
	b.WriteString("[Reconciliation Report]\n")

	if len(r.ObsidianMissing) > 0 {
		fmt.Fprintf(&b, "\nObsidian: %d files in GitHub but not in DB:\n", len(r.ObsidianMissing))
		for _, s := range r.ObsidianMissing {
			fmt.Fprintf(&b, "  + %s\n", s)
		}
	}
	if len(r.ObsidianOrphaned) > 0 {
		fmt.Fprintf(&b, "\nObsidian: %d records in DB but not in GitHub:\n", len(r.ObsidianOrphaned))
		for _, s := range r.ObsidianOrphaned {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
	}
	if len(r.ProjectsMissing) > 0 {
		fmt.Fprintf(&b, "\nProjects: %d in Notion but not in DB:\n", len(r.ProjectsMissing))
		for _, s := range r.ProjectsMissing {
			fmt.Fprintf(&b, "  + %s\n", s)
		}
	}
	if len(r.ProjectsOrphaned) > 0 {
		fmt.Fprintf(&b, "\nProjects: %d in DB but not in Notion:\n", len(r.ProjectsOrphaned))
		for _, s := range r.ProjectsOrphaned {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
	}
	if len(r.GoalsMissing) > 0 {
		fmt.Fprintf(&b, "\nGoals: %d in Notion but not in DB:\n", len(r.GoalsMissing))
		for _, s := range r.GoalsMissing {
			fmt.Fprintf(&b, "  + %s\n", s)
		}
	}
	if len(r.GoalsOrphaned) > 0 {
		fmt.Fprintf(&b, "\nGoals: %d in DB but not in Notion:\n", len(r.GoalsOrphaned))
		for _, s := range r.GoalsOrphaned {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
	}

	return b.String()
}
