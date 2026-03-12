package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"golang.org/x/sync/errgroup"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
)

// ContentStrategyOutput is the JSON output of the content-strategy flow.
type ContentStrategyOutput struct {
	Text string `json:"text"`
}

// ContentStrategy implements the content-strategy flow.
type ContentStrategy struct {
	gf        *genkitFlow
	g         *genkit.Genkit
	model     ai.Model
	contents  PublishedContentLister
	collected HighScoreLister
	projects  ActiveProjectLister
	notifier  Sender
	budget    BudgetChecker
	logger    *slog.Logger
}

// NewContentStrategy returns a ContentStrategy flow.
func NewContentStrategy(
	g *genkit.Genkit,
	model ai.Model,
	contents PublishedContentLister,
	collects HighScoreLister,
	projects ActiveProjectLister,
	notifier Sender,
	budget BudgetChecker,
	logger *slog.Logger,
) *ContentStrategy {
	cs := &ContentStrategy{
		g:         g,
		model:     model,
		contents:  contents,
		collected: collects,
		projects:  projects,
		notifier:  notifier,
		budget:    budget,
		logger:    logger,
	}
	cs.gf = genkit.DefineFlow(g, "content-strategy", func(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
		out, err := cs.run(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return cs
}

// Name returns the flow name for registry lookup.
func (cs *ContentStrategy) Name() string { return "content-strategy" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (cs *ContentStrategy) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return cs.gf.Run(ctx, input)
}

const (
	estimatedStrategyTokens int64 = 2000
	strategyMinScore        int16 = 60
)

func (cs *ContentStrategy) run(ctx context.Context) (ContentStrategyOutput, error) {
	if err := cs.budget.Check(estimatedStrategyTokens); err != nil {
		return ContentStrategyOutput{}, fmt.Errorf("budget check: %w", err)
	}

	cs.logger.Info("content-strategy starting")

	now := time.Now()
	monthAgo := now.Add(-30 * 24 * time.Hour)
	weekAgo := now.Add(-7 * 24 * time.Hour)

	var (
		published []content.Content
		pubErr    error
		rssItems  []collected.CollectedData
		rssErr    error
		projects  []project.Project
		projErr   error
	)

	g := new(errgroup.Group)
	g.Go(func() error {
		published, pubErr = cs.contents.PublishedByDateRange(ctx, monthAgo, now)
		return nil // never fail the group
	})
	g.Go(func() error {
		rssItems, rssErr = cs.collected.HighScoreCollectedData(ctx, weekAgo, now, strategyMinScore)
		return nil
	})
	g.Go(func() error {
		projects, projErr = cs.projects.ActiveProjects(ctx)
		return nil
	})
	_ = g.Wait()

	userPrompt := buildContentStrategyPrompt(published, pubErr, rssItems, rssErr, projects, projErr, monthAgo, now)

	text, err := genkit.Run(ctx, "generate-content-strategy", func() (string, error) {
		resp, err := genkit.Generate(ctx, cs.g,
			ai.WithModel(cs.model),
			ai.WithSystem(contentStrategySystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.7),
				MaxOutputTokens: 1024,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating content strategy: %w", err)
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ContentStrategyOutput{}, err
	}

	cs.budget.Add(estimatedStrategyTokens)

	if err := cs.notifier.Send(ctx, "[Content Strategy]\n"+text); err != nil {
		cs.logger.Error("sending content-strategy notification", "error", err)
	}

	cs.logger.Info("content-strategy complete",
		"published_30d", len(published),
		"rss_items_7d", len(rssItems),
		"active_projects", len(projects),
	)

	return ContentStrategyOutput{Text: text}, nil
}

func buildContentStrategyPrompt(
	published []content.Content, pubErr error,
	rssItems []collected.CollectedData, rssErr error,
	projects []project.Project, projErr error,
	start, end time.Time,
) string {
	var b strings.Builder

	fmt.Fprintf(&b, "分析期間：%s 至 %s\n\n", start.Format("2006-01-02"), end.Format("2006-01-02"))

	// Published content distribution
	b.WriteString("== 過去 30 天發佈記錄 ==\n")
	switch {
	case pubErr != nil:
		b.WriteString("發佈資料不可用\n")
	case len(published) == 0:
		b.WriteString("過去 30 天無發佈\n")
	default:
		// Count by type
		typeCounts := make(map[content.Type]int)
		for _, c := range published {
			typeCounts[c.Type]++
		}
		fmt.Fprintf(&b, "共 %d 篇\n", len(published))
		for t, count := range typeCounts {
			fmt.Fprintf(&b, "- %s: %d 篇\n", t, count)
		}
		b.WriteString("\n最近發佈：\n")
		limit := min(len(published), 5)
		for _, c := range published[:limit] {
			fmt.Fprintf(&b, "- %s（%s）\n", c.Title, c.Type)
		}
	}

	// Trending collected articles
	b.WriteString("\n== 本週高分收集文章（ai_score >= 60）==\n")
	switch {
	case rssErr != nil:
		b.WriteString("RSS 資料不可用\n")
	case len(rssItems) == 0:
		b.WriteString("無符合條件的文章\n")
	default:
		limit := min(len(rssItems), 10)
		for _, item := range rssItems[:limit] {
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
			fmt.Fprintf(&b, "- %s: %s（%s）\n", p.Title, p.Description, p.Status)
		}
	}

	// Knowledge gap analysis: compare tag distributions
	if pubErr == nil && rssErr == nil && (len(published) > 0 || len(rssItems) > 0) {
		b.WriteString("\n== 知識缺口分析 ==\n")

		ownTags := make(map[string]int)
		for _, c := range published {
			for _, tag := range c.Tags {
				ownTags[tag]++
			}
		}
		rssTags := make(map[string]int)
		for _, item := range rssItems {
			for _, tag := range item.Topics {
				rssTags[tag]++
			}
		}

		b.WriteString("自己的發佈主題分佈：\n")
		if len(ownTags) == 0 {
			b.WriteString("（無標籤資料）\n")
		} else {
			for tag, count := range ownTags {
				fmt.Fprintf(&b, "- %s: %d 篇\n", tag, count)
			}
		}

		b.WriteString("\nRSS 高分文章主題分佈：\n")
		if len(rssTags) == 0 {
			b.WriteString("（無標籤資料）\n")
		} else {
			for tag, count := range rssTags {
				fmt.Fprintf(&b, "- %s: %d 篇\n", tag, count)
			}
		}

		// Find gaps: topics in RSS but not in own content
		var gaps []string
		for tag := range rssTags {
			if ownTags[tag] == 0 {
				gaps = append(gaps, tag)
			}
		}
		if len(gaps) > 0 {
			b.WriteString("\n潛在缺口（RSS 熱門但自己未涉獵）：\n")
			for _, tag := range gaps {
				fmt.Fprintf(&b, "- %s（RSS 出現 %d 次）\n", tag, rssTags[tag])
			}
		}
	}

	return b.String()
}

// NewMockContentStrategy returns a mock Flow for MOCK_MODE.
func NewMockContentStrategy() Flow {
	return &mockContentStrategyFlow{}
}

type mockContentStrategyFlow struct{}

func (m *mockContentStrategyFlow) Name() string { return "content-strategy" }

func (m *mockContentStrategyFlow) Run(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(ContentStrategyOutput{Text: "Mock content strategy"})
}
