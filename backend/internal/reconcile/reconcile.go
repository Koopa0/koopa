// Package reconcile compares Obsidian files (via GitHub) and Notion records
// against the local database to detect drift. It runs as a weekly cron job.
//
// This is a cross-feature orchestration package: it needs data from content,
// project, goal, and notion to produce a diff report. All dependencies are
// injected via consumer-defined interfaces to avoid import cycles.
// It is intentionally a standalone package (not merged into pipeline or any
// single feature) because reconciliation spans multiple feature boundaries.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/koopa0/blog-backend/internal/notion"
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
func (r *Report) HasIssues() bool {
	return len(r.ObsidianMissing) > 0 || len(r.ObsidianOrphaned) > 0 ||
		len(r.ProjectsMissing) > 0 || len(r.ProjectsOrphaned) > 0 ||
		len(r.GoalsMissing) > 0 || len(r.GoalsOrphaned) > 0
}

// RoleLookup resolves a Notion database ID by system role.
type RoleLookup interface {
	DatabaseIDByRole(ctx context.Context, role string) (string, error)
}

// Reconciler runs weekly reconciliation checks.
type Reconciler struct {
	github   DirectoryLister
	content  ObsidianSlugLister
	projects NotionPageIDLister
	goals    NotionPageIDLister
	notionDB NotionDBQuerier
	notifier Sender
	roles    RoleLookup
	logger   *slog.Logger
}

// New returns a Reconciler.
func New(
	github DirectoryLister,
	content ObsidianSlugLister,
	projects NotionPageIDLister,
	goals NotionPageIDLister,
	notionDB NotionDBQuerier,
	notifier Sender,
	roles RoleLookup,
	logger *slog.Logger,
) *Reconciler {
	return &Reconciler{
		github:   github,
		content:  content,
		projects: projects,
		goals:    goals,
		notionDB: notionDB,
		notifier: notifier,
		roles:    roles,
		logger:   logger,
	}
}

// Run executes the full reconciliation (Obsidian + Notion) and always sends a summary notification.
func (r *Reconciler) Run(ctx context.Context) error {
	r.logger.Info("reconciliation starting")

	var obsReport, notionReport Report
	var wg sync.WaitGroup
	wg.Go(func() {
		obsReport = r.reconcileObsidian(ctx)
	})
	wg.Go(func() {
		notionReport = r.reconcileNotion(ctx)
	})
	wg.Wait()

	report := Report{
		ObsidianMissing:  obsReport.ObsidianMissing,
		ObsidianOrphaned: obsReport.ObsidianOrphaned,
		ProjectsMissing:  notionReport.ProjectsMissing,
		ProjectsOrphaned: notionReport.ProjectsOrphaned,
		GoalsMissing:     notionReport.GoalsMissing,
		GoalsOrphaned:    notionReport.GoalsOrphaned,
	}

	return r.sendReport(ctx, &report)
}

// ReconcileObsidian compares GitHub 10-Public-Content/ against local contents and sends a report.
func (r *Reconciler) ReconcileObsidian(ctx context.Context) error {
	r.logger.Info("reconcile obsidian starting")
	report := r.reconcileObsidian(ctx)
	return r.sendReport(ctx, &report)
}

// ReconcileNotion compares Notion Projects + Goals against local DB and sends a report.
func (r *Reconciler) ReconcileNotion(ctx context.Context) error {
	r.logger.Info("reconcile notion starting")
	report := r.reconcileNotion(ctx)
	return r.sendReport(ctx, &report)
}

// reconcileObsidian fetches GitHub and local slugs, returns partial report.
func (r *Reconciler) reconcileObsidian(ctx context.Context) Report {
	var (
		githubSlugs []string
		githubErr   error
		localSlugs  []string
		localErr    error
	)

	var wg sync.WaitGroup
	wg.Go(func() {
		githubSlugs, githubErr = r.github.ListDirectory(ctx, "10-Public-Content")
	})
	wg.Go(func() {
		localSlugs, localErr = r.content.ObsidianContentSlugs(ctx)
	})
	wg.Wait()

	if githubErr != nil {
		r.logger.Error("reconcile: listing github directory", "error", githubErr)
	}
	if localErr != nil {
		r.logger.Error("reconcile: listing obsidian content", "error", localErr)
	}

	var report Report
	if githubErr == nil && localErr == nil {
		report.ObsidianMissing, report.ObsidianOrphaned = diff(githubSlugs, localSlugs)
	}
	return report
}

// reconcileNotion fetches Notion and local page IDs for Projects + Goals, returns partial report.
func (r *Reconciler) reconcileNotion(ctx context.Context) Report {
	var (
		localProjIDs  []string
		localProjErr  error
		notionProjIDs []string
		notionProjErr error
		localGoalIDs  []string
		localGoalErr  error
		notionGoalIDs []string
		notionGoalErr error
	)

	var wg sync.WaitGroup
	wg.Go(func() {
		localProjIDs, localProjErr = r.projects.NotionPageIDs(ctx)
	})
	wg.Go(func() {
		projDBID, err := r.roles.DatabaseIDByRole(ctx, notion.RoleProjects)
		if err != nil {
			r.logger.Warn("reconcile: skipping projects, role lookup failed", "error", err)
			return
		}
		notionProjIDs, notionProjErr = r.notionDB.QueryPageIDs(ctx, projDBID)
	})
	wg.Go(func() {
		localGoalIDs, localGoalErr = r.goals.NotionPageIDs(ctx)
	})
	wg.Go(func() {
		goalsDBID, err := r.roles.DatabaseIDByRole(ctx, notion.RoleGoals)
		if err != nil {
			r.logger.Warn("reconcile: skipping goals, role lookup failed", "error", err)
			return
		}
		notionGoalIDs, notionGoalErr = r.notionDB.QueryPageIDs(ctx, goalsDBID)
	})
	wg.Wait()

	var report Report

	if localProjErr != nil {
		r.logger.Error("reconcile: listing local project page ids", "error", localProjErr)
	}
	if notionProjErr != nil {
		r.logger.Error("reconcile: querying notion projects", "error", notionProjErr)
	}
	if localProjErr == nil && notionProjErr == nil && len(notionProjIDs) > 0 {
		report.ProjectsMissing, report.ProjectsOrphaned = diff(notionProjIDs, localProjIDs)
	}

	if localGoalErr != nil {
		r.logger.Error("reconcile: listing local goal page ids", "error", localGoalErr)
	}
	if notionGoalErr != nil {
		r.logger.Error("reconcile: querying notion goals", "error", notionGoalErr)
	}
	if localGoalErr == nil && notionGoalErr == nil && len(notionGoalIDs) > 0 {
		report.GoalsMissing, report.GoalsOrphaned = diff(notionGoalIDs, localGoalIDs)
	}

	return report
}

// sendReport always sends a reconciliation summary notification.
func (r *Reconciler) sendReport(ctx context.Context, report *Report) error {
	if !report.HasIssues() {
		r.logger.Info("reconciliation complete, no issues found")
		if err := r.notifier.Send(ctx, "Reconcile complete: all consistent"); err != nil {
			return fmt.Errorf("sending reconciliation report: %w", err)
		}
		return nil
	}

	text := formatReport(report)
	r.logger.Warn("reconciliation found issues", "report", text)

	if err := r.notifier.Send(ctx, text); err != nil {
		return fmt.Errorf("sending reconciliation report: %w", err)
	}
	return nil
}

// diff returns items in source but not in target (missing), and items in target but not in source (orphaned).
func diff(source, target []string) (missing, orphaned []string) {
	sourceSet := make(map[string]struct{}, len(source))
	for _, s := range source {
		sourceSet[s] = struct{}{}
	}
	targetSet := make(map[string]struct{}, len(target))
	for _, t := range target {
		targetSet[t] = struct{}{}
	}

	for _, s := range source {
		if _, ok := targetSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	for _, t := range target {
		if _, ok := sourceSet[t]; !ok {
			orphaned = append(orphaned, t)
		}
	}
	return missing, orphaned
}

func formatReport(r *Report) string {
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
