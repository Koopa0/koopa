package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
)

// CommitLister lists recent commits from a source repository.
type CommitLister interface {
	RecentCommits(ctx context.Context, since time.Time) ([]pipeline.Commit, error)
}

// TaskCompletionCounter counts tasks completed since a given time.
// ProjectCompletion holds a per-project completion count.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// TaskCompletionCounter counts tasks completed since a given time.
type TaskCompletionCounter interface {
	CompletedSince(ctx context.Context, since time.Time) (int64, error)
	CompletedByProjectSince(ctx context.Context, since time.Time) ([]ProjectCompletion, error)
}

// WeeklyReviewOutput is the JSON output of the weekly-review flow.
type WeeklyReviewOutput struct {
	Text string `json:"text"`
}

// WeeklyReview implements the weekly-review flow.
type WeeklyReview struct {
	gf             *genkitFlow
	g              *genkit.Genkit
	model          ai.Model
	tasks          TaskQuerier
	taskCompletion TaskCompletionCounter
	collected      HighScoreLister
	contents       PublishedContentLister
	projects       ActiveProjectLister
	commits        CommitLister
	notifier       Sender
	budget         BudgetChecker
	loc            *time.Location
	logger         *slog.Logger
}

// NewWeeklyReview returns a WeeklyReview flow.
func NewWeeklyReview(
	g *genkit.Genkit,
	model ai.Model,
	tasks TaskQuerier,
	taskCompletion TaskCompletionCounter,
	collects HighScoreLister,
	contents PublishedContentLister,
	projects ActiveProjectLister,
	commits CommitLister,
	notifier Sender,
	budget BudgetChecker,
	loc *time.Location,
	logger *slog.Logger,
) *WeeklyReview {
	wr := &WeeklyReview{
		g:              g,
		model:          model,
		tasks:          tasks,
		taskCompletion: taskCompletion,
		collected:      collects,
		contents:       contents,
		projects:       projects,
		commits:        commits,
		notifier:       notifier,
		budget:         budget,
		loc:            loc,
		logger:         logger,
	}
	wr.gf = genkit.DefineFlow(g, "weekly-review", func(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
		out, err := wr.run(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return wr
}

// Name returns the flow name for registry lookup.
func (wr *WeeklyReview) Name() string { return "weekly-review" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (wr *WeeklyReview) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return wr.gf.Run(ctx, input)
}

const (
	estimatedReviewTokens int64 = 3000
	reviewMinScore        int16 = 60
)

func (wr *WeeklyReview) run(ctx context.Context) (WeeklyReviewOutput, error) {
	if err := wr.budget.Reserve(estimatedReviewTokens); err != nil {
		return WeeklyReviewOutput{}, fmt.Errorf("budget reserve: %w", err)
	}

	wr.logger.Info("weekly-review starting")

	now := time.Now().In(wr.loc)
	weekAgo := now.Add(-7 * 24 * time.Hour)

	// Gather data sources in parallel — individual failures are degraded, not fatal
	var (
		tasks            []PendingTask
		taskErr          error
		completedCount   int64
		completedErr     error
		completedByProj  []ProjectCompletion
		completedProjErr error
		rssItems         []collected.CollectedData
		rssErr           error
		published        []content.Content
		pubErr           error
		projects         []project.Project
		projErr          error
		commits          []pipeline.Commit
		commitErr        error
	)

	var wg sync.WaitGroup
	wg.Go(func() {
		tasks, taskErr = wr.tasks.PendingTasks(ctx)
	})
	wg.Go(func() {
		completedCount, completedErr = wr.taskCompletion.CompletedSince(ctx, weekAgo)
	})
	wg.Go(func() {
		completedByProj, completedProjErr = wr.taskCompletion.CompletedByProjectSince(ctx, weekAgo)
	})
	wg.Go(func() {
		rssItems, rssErr = wr.collected.HighScoreCollectedData(ctx, weekAgo, now, reviewMinScore)
	})
	wg.Go(func() {
		published, pubErr = wr.contents.PublishedByDateRange(ctx, weekAgo, now)
	})
	wg.Go(func() {
		projects, projErr = wr.projects.ActiveProjects(ctx)
	})
	wg.Go(func() {
		commits, commitErr = wr.commits.RecentCommits(ctx, weekAgo)
	})
	wg.Wait()

	userPrompt := buildWeeklyReviewPrompt(
		tasks, taskErr,
		completedCount, completedErr,
		completedByProj, completedProjErr,
		rssItems, rssErr,
		published, pubErr,
		projects, projErr,
		commits, commitErr,
		weekAgo, now,
	)

	text, err := genkit.Run(ctx, "generate-weekly-review", func() (string, error) {
		resp, err := genkit.Generate(ctx, wr.g,
			ai.WithModel(wr.model),
			ai.WithSystem(weeklyReviewSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 2048,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating weekly review: %w", err)
		}
		if err := checkFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return WeeklyReviewOutput{}, err
	}

	if err := wr.notifier.Send(ctx, text); err != nil {
		wr.logger.Error("sending weekly review notification", "error", err)
	}

	wr.logger.Info("weekly-review complete",
		"tasks", len(tasks),
		"rss_items", len(rssItems),
		"published", len(published),
		"projects", len(projects),
		"commits", len(commits),
	)

	return WeeklyReviewOutput{Text: text}, nil
}

func buildWeeklyReviewPrompt(
	tasks []PendingTask, taskErr error,
	completedCount int64, completedErr error,
	completedByProj []ProjectCompletion, completedProjErr error,
	rssItems []collected.CollectedData, rssErr error,
	published []content.Content, pubErr error,
	projects []project.Project, projErr error,
	commits []pipeline.Commit, commitErr error,
	start, end time.Time,
) string {
	var b strings.Builder

	fmt.Fprintf(&b, "回顧期間：%s 至 %s\n\n", start.Format("2006-01-02"), end.Format("2006-01-02"))

	// Published content
	b.WriteString("== 本週發佈 ==\n")
	switch {
	case pubErr != nil:
		b.WriteString("發佈資料不可用\n")
	case len(published) == 0:
		b.WriteString("本週無發佈\n")
	default:
		for _, c := range published {
			fmt.Fprintf(&b, "- %s（%s）\n", c.Title, c.Type)
		}
	}

	// GitHub commits
	b.WriteString("\n== GitHub 活動 ==\n")
	switch {
	case commitErr != nil:
		b.WriteString("GitHub 資料不可用\n")
	case len(commits) == 0:
		b.WriteString("本週無 commit\n")
	default:
		fmt.Fprintf(&b, "共 %d 筆 commit\n", len(commits))
		limit := min(len(commits), 10)
		for _, c := range commits[:limit] {
			fmt.Fprintf(&b, "- %s %s\n", c.SHA, c.Message)
		}
		if len(commits) > 10 {
			fmt.Fprintf(&b, "...（還有 %d 筆）\n", len(commits)-10)
		}
	}

	// High-score articles
	b.WriteString("\n== 本週值得關注的文章（ai_score >= 60）==\n")
	switch {
	case rssErr != nil:
		b.WriteString("RSS 資料不可用\n")
	case len(rssItems) == 0:
		b.WriteString("無符合條件的文章\n")
	default:
		for _, item := range rssItems {
			title := item.Title
			if item.AITitleZH != nil {
				title = *item.AITitleZH
			}
			fmt.Fprintf(&b, "- %s（%s）\n", title, item.SourceName)
		}
	}

	// Active projects
	b.WriteString("\n== 活躍專案 ==\n")
	switch {
	case projErr != nil:
		b.WriteString("專案資料不可用\n")
	case len(projects) == 0:
		b.WriteString("無活躍專案\n")
	default:
		for _, p := range projects {
			fmt.Fprintf(&b, "- %s（%s）\n", p.Title, p.Status)
		}
	}

	// Task completion stats
	b.WriteString("\n== 任務完成統計 ==\n")
	if completedErr != nil {
		b.WriteString("完成統計不可用\n")
	} else {
		fmt.Fprintf(&b, "本週完成 %d 個任務\n", completedCount)
	}
	if completedProjErr == nil && len(completedByProj) > 0 {
		b.WriteString("按專案分佈：\n")
		for _, pc := range completedByProj {
			fmt.Fprintf(&b, "  - %s：%d 個\n", pc.ProjectTitle, pc.Completed)
		}
	}

	// Pending tasks
	b.WriteString("\n== 待辦事項 ==\n")
	switch {
	case taskErr != nil:
		b.WriteString("任務資料不可用\n")
	case len(tasks) == 0:
		b.WriteString("無待辦事項\n")
	default:
		for _, t := range tasks {
			if t.Due != "" {
				fmt.Fprintf(&b, "- %s（截止：%s）\n", t.Title, t.Due)
			} else {
				fmt.Fprintf(&b, "- %s\n", t.Title)
			}
		}
	}

	return b.String()
}

// NewMockWeeklyReview returns a mock Flow for MOCK_MODE.
func NewMockWeeklyReview() Flow {
	return &mockFlow{
		name:   "weekly-review",
		output: WeeklyReviewOutput{Text: "Mock weekly review"},
	}
}
