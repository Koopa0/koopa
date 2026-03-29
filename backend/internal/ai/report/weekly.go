package report

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
)

// WeeklyInput is optional JSON input passed via Runner.Submit.
// Health data is gathered at the cron layer and passed in as input.
type WeeklyInput struct {
	HealthIssues []string `json:"health_issues,omitempty"`
}

// ProjectCompletion is a convenience alias for ai.ProjectCompletion.
type ProjectCompletion = ai.ProjectCompletion

// WeeklyOutput is the JSON output of the weekly-review flow.
type WeeklyOutput struct {
	Text string `json:"text"`
}

// Weekly implements the weekly-review flow.
type Weekly struct {
	gf             *ai.GenkitFlow
	g              *genkit.Genkit
	model          genkitai.Model
	systemPrompt   string
	tasks          *task.Store
	taskCompletion *task.Store
	collected      *entry.Store
	contents       *content.Store
	projects       *project.Store
	commits        *github.Client
	notifier       notify.Notifier
	budget         *budget.Budget
	loc            *time.Location
	logger         *slog.Logger
}

// NewWeekly returns a Weekly flow.
func NewWeekly(
	g *genkit.Genkit,
	model genkitai.Model,
	systemPrompt string,
	tasks *task.Store,
	taskCompletion *task.Store,
	collects *entry.Store,
	contents *content.Store,
	projects *project.Store,
	commits *github.Client,
	notifier notify.Notifier,
	tokenBudget *budget.Budget,
	loc *time.Location,
	logger *slog.Logger,
) *Weekly {
	wr := &Weekly{
		g:              g,
		model:          model,
		systemPrompt:   systemPrompt,
		tasks:          tasks,
		taskCompletion: taskCompletion,
		collected:      collects,
		contents:       contents,
		projects:       projects,
		commits:        commits,
		notifier:       notifier,
		budget:         tokenBudget,
		loc:            loc,
		logger:         logger,
	}
	wr.gf = genkit.DefineFlow(g, "weekly-review", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		out, err := wr.run(ctx, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return wr
}

// Name returns the flow name for registry lookup.
func (wr *Weekly) Name() string { return "weekly-review" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (wr *Weekly) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return wr.gf.Run(ctx, input)
}

const (
	estimatedReviewTokens int64 = 3000
	reviewCollectedLimit  int32 = 30
)

func (wr *Weekly) run(ctx context.Context, rawInput json.RawMessage) (WeeklyOutput, error) {
	if err := wr.budget.Reserve(estimatedReviewTokens); err != nil {
		return WeeklyOutput{}, fmt.Errorf("budget reserve: %w", err)
	}

	wr.logger.Info("weekly-review starting")

	// Parse optional input (health data from cron layer).
	var input WeeklyInput
	if len(rawInput) > 0 {
		_ = json.Unmarshal(rawInput, &input) // best-effort: empty input is fine
	}

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
		rssItems         []entry.Item
		rssErr           error
		published        []content.Content
		pubErr           error
		activeProjects   []project.Project
		projErr          error
		commits          []github.Commit
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
		rssItems, rssErr = wr.collected.RecentCollectedData(ctx, weekAgo, now, reviewCollectedLimit)
	})
	wg.Go(func() {
		published, pubErr = wr.contents.PublishedByDateRange(ctx, weekAgo, now)
	})
	wg.Go(func() {
		activeProjects, projErr = wr.projects.ActiveProjects(ctx)
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
		activeProjects, projErr,
		commits, commitErr,
		input.HealthIssues,
		weekAgo, now,
	)

	text, err := genkit.Run(ctx, "generate-weekly-review", func() (string, error) {
		resp, err := genkit.Generate(ctx, wr.g,
			genkitai.WithModel(wr.model),
			genkitai.WithSystem(wr.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 2048,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating weekly review: %w", err)
		}
		if err := ai.CheckFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return WeeklyOutput{}, err
	}

	if err := wr.notifier.Send(ctx, text); err != nil {
		wr.logger.Error("sending weekly review notification", "error", err)
	}

	wr.logger.Info("weekly-review complete",
		"tasks", len(tasks),
		"rss_items", len(rssItems),
		"published", len(published),
		"projects", len(activeProjects),
		"commits", len(commits),
	)

	return WeeklyOutput{Text: text}, nil
}

func buildWeeklyReviewPrompt(
	tasks []PendingTask, taskErr error,
	completedCount int64, completedErr error,
	completedByProj []ProjectCompletion, completedProjErr error,
	rssItems []entry.Item, rssErr error,
	published []content.Content, pubErr error,
	projects []project.Project, projErr error,
	commits []github.Commit, commitErr error,
	healthIssues []string,
	start, end time.Time,
) string {
	var b strings.Builder

	writeWeeklyHealthSection(&b, healthIssues)
	fmt.Fprintf(&b, "回顧期間：%s 至 %s\n\n", start.Format("2006-01-02"), end.Format("2006-01-02"))
	writeWeeklyPublishedSection(&b, published, pubErr)
	writeWeeklyCommitsSection(&b, commits, commitErr)
	writeWeeklyCollectedSection(&b, rssItems, rssErr)
	writeWeeklyProjectsSection(&b, projects, projErr)
	writeWeeklyCompletionSection(&b, completedCount, completedErr, completedByProj, completedProjErr)
	writeWeeklyTasksSection(&b, tasks, taskErr)

	return b.String()
}

func writeWeeklyHealthSection(b *strings.Builder, healthIssues []string) {
	if len(healthIssues) == 0 {
		return
	}
	b.WriteString("⚠️ == 系統健康警告 ==\n")
	for _, issue := range healthIssues {
		fmt.Fprintf(b, "- %s\n", issue)
	}
	b.WriteByte('\n')
}

func writeWeeklyPublishedSection(b *strings.Builder, published []content.Content, pubErr error) {
	b.WriteString("== 本週發佈 ==\n")
	switch {
	case pubErr != nil:
		b.WriteString("發佈資料不可用\n")
	case len(published) == 0:
		b.WriteString("本週無發佈\n")
	default:
		for i := range published {
			c := &published[i]
			fmt.Fprintf(b, "- %s（%s）\n", c.Title, c.Type)
		}
	}
}

func writeWeeklyCommitsSection(b *strings.Builder, commits []github.Commit, commitErr error) {
	b.WriteString("\n== GitHub 活動 ==\n")
	switch {
	case commitErr != nil:
		b.WriteString("GitHub 資料不可用\n")
	case len(commits) == 0:
		b.WriteString("本週無 commit\n")
	default:
		fmt.Fprintf(b, "共 %d 筆 commit\n", len(commits))
		limit := min(len(commits), 10)
		for _, c := range commits[:limit] {
			fmt.Fprintf(b, "- %s %s\n", c.SHA, c.Message)
		}
		if len(commits) > 10 {
			fmt.Fprintf(b, "...（還有 %d 筆）\n", len(commits)-10)
		}
	}
}

func writeWeeklyCollectedSection(b *strings.Builder, rssItems []entry.Item, rssErr error) {
	b.WriteString("\n== 本週值得關注的文章 ==\n")
	switch {
	case rssErr != nil:
		b.WriteString("RSS 資料不可用\n")
	case len(rssItems) == 0:
		b.WriteString("無符合條件的文章\n")
	default:
		for i := range rssItems {
			fmt.Fprintf(b, "- %s（%s）\n", rssItems[i].Title, rssItems[i].SourceName)
		}
	}
}

func writeWeeklyProjectsSection(b *strings.Builder, projects []project.Project, projErr error) {
	b.WriteString("\n== 活躍專案 ==\n")
	switch {
	case projErr != nil:
		b.WriteString("專案資料不可用\n")
	case len(projects) == 0:
		b.WriteString("無活躍專案\n")
	default:
		for i := range projects {
			fmt.Fprintf(b, "- %s（%s）\n", projects[i].Title, projects[i].Status)
		}
	}
}

func writeWeeklyCompletionSection(b *strings.Builder, completedCount int64, completedErr error, completedByProj []ProjectCompletion, completedProjErr error) {
	b.WriteString("\n== 任務完成統計 ==\n")
	if completedErr != nil {
		b.WriteString("完成統計不可用\n")
	} else {
		fmt.Fprintf(b, "本週完成 %d 個任務\n", completedCount)
	}
	if completedProjErr == nil && len(completedByProj) > 0 {
		b.WriteString("按專案分佈：\n")
		for _, pc := range completedByProj {
			fmt.Fprintf(b, "  - %s：%d 個\n", pc.ProjectTitle, pc.Completed)
		}
	}
}

func writeWeeklyTasksSection(b *strings.Builder, tasks []PendingTask, taskErr error) {
	b.WriteString("\n== 待辦事項 ==\n")
	switch {
	case taskErr != nil:
		b.WriteString("任務資料不可用\n")
	case len(tasks) == 0:
		b.WriteString("無待辦事項\n")
	default:
		for _, t := range tasks {
			if t.Due != "" {
				fmt.Fprintf(b, "- %s（截止：%s）\n", t.Title, t.Due)
			} else {
				fmt.Fprintf(b, "- %s\n", t.Title)
			}
		}
	}
}
