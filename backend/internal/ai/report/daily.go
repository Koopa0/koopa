package report

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/budget"
)

// DailyInput is the optional JSON input for the daily-dev-log flow.
// When empty, defaults to yesterday in the configured timezone.
type DailyInput struct {
	Date string `json:"date,omitempty"` // YYYY-MM-DD, defaults to yesterday
}

// DailyOutput is the JSON output of the daily-dev-log flow.
type DailyOutput struct {
	Date     string `json:"date"`
	Markdown string `json:"markdown"`
	Events   int    `json:"events"` // total activity events processed
}

// Daily implements the daily-dev-log flow using Genkit.
type Daily struct {
	gf           *ai.GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	events       *activity.Store
	notifier     ai.Sender
	budget       *budget.Budget
	loc          *time.Location
	logger       *slog.Logger
}

// NewDaily returns a Daily flow.
func NewDaily(
	g *genkit.Genkit,
	model genkitai.Model,
	systemPrompt string,
	events *activity.Store,
	notifier ai.Sender,
	tokenBudget *budget.Budget,
	loc *time.Location,
	logger *slog.Logger,
) *Daily {
	ddl := &Daily{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		events:       events,
		notifier:     notifier,
		budget:       tokenBudget,
		loc:          loc,
		logger:       logger,
	}
	ddl.gf = genkit.DefineFlow(g, "daily-dev-log", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DailyInput
		if len(input) > 0 {
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, fmt.Errorf("parsing daily-dev-log input: %w", err)
			}
		}
		out, err := ddl.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return ddl
}

// Name returns the flow name for registry lookup.
func (ddl *Daily) Name() string { return "daily-dev-log" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (ddl *Daily) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return ddl.gf.Run(ctx, input)
}

const estimatedDevLogTokens int64 = 2000

func (ddl *Daily) run(ctx context.Context, in DailyInput) (DailyOutput, error) {
	if err := ddl.budget.Reserve(estimatedDevLogTokens); err != nil {
		return DailyOutput{}, fmt.Errorf("budget reserve: %w", err)
	}

	// determine target date — midnight in configured timezone
	now := time.Now().In(ddl.loc)
	var targetDate time.Time
	if in.Date != "" {
		parsed, err := time.ParseInLocation("2006-01-02", in.Date, ddl.loc)
		if err != nil {
			return DailyOutput{}, fmt.Errorf("parsing date: %w", err)
		}
		targetDate = parsed
	} else {
		// yesterday at midnight in loc (not UTC)
		y, m, d := now.Date()
		targetDate = time.Date(y, m, d-1, 0, 0, 0, 0, ddl.loc)
	}

	start := targetDate
	end := targetDate.Add(24 * time.Hour)
	dateStr := targetDate.Format("2006-01-02")

	ddl.logger.Info("daily-dev-log starting", "date", dateStr)

	events, err := ddl.events.EventsByTimeRange(ctx, start, end)
	if err != nil {
		return DailyOutput{}, fmt.Errorf("querying events: %w", err)
	}

	// no events — return a short message without calling the LLM
	if len(events) == 0 {
		noActivity := fmt.Sprintf("# Daily Dev Log — %s\n\n今天沒有記錄到任何開發活動。", dateStr)
		return DailyOutput{
			Date:     dateStr,
			Markdown: noActivity,
			Events:   0,
		}, nil
	}

	userPrompt := buildDailyDevLogPrompt(dateStr, events)

	markdown, err := genkit.Run(ctx, "generate-daily-dev-log", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, ddl.g,
			genkitai.WithModel(ddl.model),
			genkitai.WithSystem(ddl.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.4),
				MaxOutputTokens: 2048,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating daily dev log: %w", genErr)
		}
		if finishErr := ai.CheckFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return DailyOutput{}, err
	}

	// send notification (best-effort)
	if ddl.notifier != nil {
		if err := ddl.notifier.Send(ctx, markdown); err != nil {
			ddl.logger.Error("sending daily dev log notification", "error", err)
		}
	}

	ddl.logger.Info("daily-dev-log complete", "date", dateStr, "events", len(events))

	return DailyOutput{
		Date:     dateStr,
		Markdown: markdown,
		Events:   len(events),
	}, nil
}

// buildDailyDevLogPrompt assembles activity events into a user prompt.
func buildDailyDevLogPrompt(date string, events []activity.Event) string {
	var b strings.Builder

	fmt.Fprintf(&b, "日期：%s\n事件數量：%d\n\n", date, len(events))

	// group events by source
	github := groupBySource(events, "github")
	obsidian := groupBySource(events, "obsidian")
	other := excludeSources(events, "github", "obsidian")

	if len(github) > 0 {
		b.WriteString("== GitHub Events ==\n")
		for i := range github {
			e := github[i]
			repo := deref(e.Repo)
			title := deref(e.Title)
			fmt.Fprintf(&b, "- [%s] %s: %s\n", e.EventType, repo, title)
		}
		b.WriteString("\n")
	}

	if len(obsidian) > 0 {
		b.WriteString("== Obsidian Events ==\n")
		for i := range obsidian {
			e := &obsidian[i]
			title := deref(e.Title)
			fmt.Fprintf(&b, "- [%s] %s\n", e.EventType, title)
		}
		b.WriteString("\n")
	}

	if len(other) > 0 {
		b.WriteString("== Other Events ==\n")
		for i := range other {
			e := &other[i]
			title := deref(e.Title)
			fmt.Fprintf(&b, "- [%s/%s] %s\n", e.Source, e.EventType, title)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func groupBySource(events []activity.Event, source string) []activity.Event {
	var result []activity.Event
	for i := range events {
		if events[i].Source == source {
			result = append(result, events[i])
		}
	}
	return result
}

func excludeSources(events []activity.Event, sources ...string) []activity.Event {
	exclude := make(map[string]bool, len(sources))
	for _, s := range sources {
		exclude[s] = true
	}
	var result []activity.Event
	for i := range events {
		if !exclude[events[i].Source] {
			result = append(result, events[i])
		}
	}
	return result
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
