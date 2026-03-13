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
)

// TaskQuerier queries pending tasks from an external source.
type TaskQuerier interface {
	PendingTasks(ctx context.Context) ([]PendingTask, error)
}

// PublishedCounter counts published content since a given time.
type PublishedCounter interface {
	PublishedContentCountSince(ctx context.Context, since time.Time) (int64, error)
}

// Sender sends a text notification.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// PendingTask represents a task pending completion.
type PendingTask struct {
	Title string
	Due   string // YYYY-MM-DD or empty
}

// MorningBriefOutput is the JSON output of the morning-brief flow.
type MorningBriefOutput struct {
	Text string `json:"text"`
}

// MorningBrief implements the morning-brief flow.
type MorningBrief struct {
	gf        *genkitFlow
	g         *genkit.Genkit
	model     ai.Model
	tasks     TaskQuerier
	collected HighScoreLister
	contents  PublishedCounter
	notifier  Sender
	budget    BudgetChecker
	loc       *time.Location
	logger    *slog.Logger
}

// NewMorningBrief returns a MorningBrief flow.
func NewMorningBrief(
	g *genkit.Genkit,
	model ai.Model,
	tasks TaskQuerier,
	collects HighScoreLister,
	contents PublishedCounter,
	notifier Sender,
	budget BudgetChecker,
	loc *time.Location,
	logger *slog.Logger,
) *MorningBrief {
	mb := &MorningBrief{
		g:         g,
		model:     model,
		tasks:     tasks,
		collected: collects,
		contents:  contents,
		notifier:  notifier,
		budget:    budget,
		loc:       loc,
		logger:    logger,
	}
	mb.gf = genkit.DefineFlow(g, "morning-brief", func(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
		out, err := mb.run(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return mb
}

// Name returns the flow name for registry lookup.
func (mb *MorningBrief) Name() string { return "morning-brief" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (mb *MorningBrief) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return mb.gf.Run(ctx, input)
}

const (
	estimatedBriefTokens int64 = 2000
	briefMinScore        int16 = 70
)

func (mb *MorningBrief) run(ctx context.Context) (MorningBriefOutput, error) {
	if err := mb.budget.Reserve(estimatedBriefTokens); err != nil {
		return MorningBriefOutput{}, fmt.Errorf("budget reserve: %w", err)
	}

	mb.logger.Info("morning-brief starting")

	// Gather data sources in parallel — individual failures are degraded, not fatal
	var (
		tasks    []PendingTask
		taskErr  error
		rssItems []collected.CollectedData
		rssErr   error
		pubCount int64
		pubErr   error
	)

	now := time.Now().In(mb.loc)
	yesterday := now.Add(-24 * time.Hour)
	weekAgo := now.Add(-7 * 24 * time.Hour)

	var wg sync.WaitGroup
	wg.Go(func() {
		tasks, taskErr = mb.tasks.PendingTasks(ctx)
	})
	wg.Go(func() {
		rssItems, rssErr = mb.collected.HighScoreCollectedData(ctx, yesterday, now, briefMinScore)
	})
	wg.Go(func() {
		pubCount, pubErr = mb.contents.PublishedContentCountSince(ctx, weekAgo)
	})
	wg.Wait()

	// Build user prompt with degraded sections
	userPrompt := buildMorningBriefPrompt(now, tasks, taskErr, rssItems, rssErr, pubCount, pubErr)

	text, err := genkit.Run(ctx, "generate-morning-brief", func() (string, error) {
		resp, err := genkit.Generate(ctx, mb.g,
			ai.WithModel(mb.model),
			ai.WithSystem(morningBriefSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.5),
				MaxOutputTokens: 1024,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating morning brief: %w", err)
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return MorningBriefOutput{}, err
	}

	// Send notification
	if err := mb.notifier.Send(ctx, text); err != nil {
		mb.logger.Error("sending morning brief notification", "error", err)
		// still return success — the brief was generated, notification failure is non-fatal
	}

	mb.logger.Info("morning-brief complete",
		"tasks", len(tasks),
		"rss_items", len(rssItems),
		"published_count", pubCount,
	)

	return MorningBriefOutput{Text: text}, nil
}

// buildMorningBriefPrompt builds the user prompt with degraded sections for failures.
func buildMorningBriefPrompt(
	now time.Time,
	tasks []PendingTask, taskErr error,
	rssItems []collected.CollectedData, rssErr error,
	pubCount int64, pubErr error,
) string {
	var b strings.Builder

	b.WriteString("今天日期：" + now.Format("2006-01-02") + "\n\n")

	// Tasks section
	b.WriteString("== 待辦事項 ==\n")
	switch {
	case taskErr != nil:
		b.WriteString("Notion 資料不可用\n")
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

	// RSS section
	b.WriteString("\n== 值得關注的文章（昨日，ai_score >= 70）==\n")
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
			summary := ""
			if item.AISummaryZH != nil {
				summary = *item.AISummaryZH
			}
			fmt.Fprintf(&b, "- %s（%s）\n  %s\n", title, item.SourceName, summary)
		}
	}

	// Published stats section
	b.WriteString("\n== 發佈統計（近 7 天）==\n")
	if pubErr != nil {
		b.WriteString("文章統計不可用\n")
	} else {
		fmt.Fprintf(&b, "發佈 %d 篇文章\n", pubCount)
	}

	return b.String()
}

// NewMockMorningBrief returns a mock Flow for MOCK_MODE.
func NewMockMorningBrief() Flow {
	return &mockFlow{
		name:   "morning-brief",
		output: MorningBriefOutput{Text: "Mock morning brief"},
	}
}
