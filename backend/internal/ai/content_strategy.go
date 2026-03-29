package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/project"
)

// ContentStrategyOutput is the JSON output of the content-strategy flow.
type ContentStrategyOutput struct {
	Text string `json:"text"`
}

// ContentStrategy implements the content-strategy flow.
type ContentStrategy struct {
	gf        *GenkitFlow
	g         *genkit.Genkit
	model     genkitai.Model
	contents  *content.Store
	collected *entry.Store
	projects  *project.Store
	notifier  Sender
	budget    *budget.Budget
	loc       *time.Location
	logger    *slog.Logger
}

// NewContentStrategy returns a ContentStrategy flow.
func NewContentStrategy(
	g *genkit.Genkit,
	model genkitai.Model,
	contents *content.Store,
	collects *entry.Store,
	projects *project.Store,
	notifier Sender,
	tokenBudget *budget.Budget,
	loc *time.Location,
	logger *slog.Logger,
) *ContentStrategy {
	cs := &ContentStrategy{
		g:         g,
		model:     model,
		contents:  contents,
		collected: collects,
		projects:  projects,
		notifier:  notifier,
		budget:    tokenBudget,
		loc:       loc,
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
	strategyCollectedLimit  int32 = 30
)

func (cs *ContentStrategy) run(ctx context.Context) (ContentStrategyOutput, error) {
	if err := cs.budget.Reserve(estimatedStrategyTokens); err != nil {
		return ContentStrategyOutput{}, fmt.Errorf("budget reserve: %w", err)
	}

	cs.logger.Info("content-strategy starting")

	now := time.Now().In(cs.loc)
	monthAgo := now.Add(-30 * 24 * time.Hour)
	weekAgo := now.Add(-7 * 24 * time.Hour)

	var (
		published []content.Content
		pubErr    error
		rssItems  []entry.Item
		rssErr    error
		projects  []project.Project
		projErr   error
	)

	var wg sync.WaitGroup
	wg.Go(func() {
		published, pubErr = cs.contents.PublishedByDateRange(ctx, monthAgo, now)
	})
	wg.Go(func() {
		rssItems, rssErr = cs.collected.RecentCollectedData(ctx, weekAgo, now, strategyCollectedLimit)
	})
	wg.Go(func() {
		projects, projErr = cs.projects.ActiveProjects(ctx)
	})
	wg.Wait()

	userPrompt := buildContentStrategyPrompt(published, pubErr, rssItems, rssErr, projects, projErr, monthAgo, now)

	text, err := genkit.Run(ctx, "generate-content-strategy", func() (string, error) {
		resp, err := genkit.Generate(ctx, cs.g,
			genkitai.WithModel(cs.model),
			genkitai.WithSystem(contentStrategySystemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.7),
				MaxOutputTokens: 2048,
			}),
		)
		if err != nil {
			return "", fmt.Errorf("generating content strategy: %w", err)
		}
		if err := CheckFinishReason(resp); err != nil {
			return "", err
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ContentStrategyOutput{}, err
	}

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
	rssItems []entry.Item, rssErr error,
	projects []project.Project, projErr error,
	start, end time.Time,
) string {
	var b strings.Builder

	fmt.Fprintf(&b, "分析期間：%s 至 %s\n\n", start.Format("2006-01-02"), end.Format("2006-01-02"))
	writePublishedSection(&b, published, pubErr)
	writeTrendingSection(&b, rssItems, rssErr)
	writeProjectsSection(&b, projects, projErr)

	if pubErr == nil && rssErr == nil && (len(published) > 0 || len(rssItems) > 0) {
		writeKnowledgeGapSection(&b, published, rssItems)
	}

	return b.String()
}

func writePublishedSection(b *strings.Builder, published []content.Content, pubErr error) {
	b.WriteString("== 過去 30 天發佈記錄 ==\n")
	switch {
	case pubErr != nil:
		b.WriteString("發佈資料不可用\n")
	case len(published) == 0:
		b.WriteString("過去 30 天無發佈\n")
	default:
		typeCounts := make(map[content.Type]int)
		for i := range published {
			typeCounts[published[i].Type]++
		}
		fmt.Fprintf(b, "共 %d 篇\n", len(published))
		for _, t := range slices.Sorted(maps.Keys(typeCounts)) {
			fmt.Fprintf(b, "- %s: %d 篇\n", t, typeCounts[t])
		}
		b.WriteString("\n最近發佈：\n")
		limit := min(len(published), 5)
		for i := range published[:limit] {
			c := &published[i]
			fmt.Fprintf(b, "- %s（%s）\n", c.Title, c.Type)
		}
	}
}

func writeTrendingSection(b *strings.Builder, rssItems []entry.Item, rssErr error) {
	b.WriteString("\n== 本週高分收集文章（ai_score >= 60）==\n")
	switch {
	case rssErr != nil:
		b.WriteString("RSS 資料不可用\n")
	case len(rssItems) == 0:
		b.WriteString("無符合條件的文章\n")
	default:
		limit := min(len(rssItems), 10)
		for i := range rssItems[:limit] {
			fmt.Fprintf(b, "- %s（%s）\n", rssItems[i].Title, rssItems[i].SourceName)
		}
	}
}

func writeProjectsSection(b *strings.Builder, projects []project.Project, projErr error) {
	b.WriteString("\n== 活躍專案 ==\n")
	switch {
	case projErr != nil:
		b.WriteString("專案資料不可用\n")
	case len(projects) == 0:
		b.WriteString("無活躍專案\n")
	default:
		for i := range projects {
			p := &projects[i]
			fmt.Fprintf(b, "- %s: %s（%s）\n", p.Title, p.Description, p.Status)
		}
	}
}

func writeKnowledgeGapSection(b *strings.Builder, published []content.Content, rssItems []entry.Item) {
	b.WriteString("\n== 知識缺口分析 ==\n")

	ownTags := make(map[string]int)
	for i := range published {
		for _, tag := range published[i].Tags {
			ownTags[tag]++
		}
	}
	rssTags := make(map[string]int)
	for i := range rssItems {
		for _, tag := range rssItems[i].Topics {
			rssTags[tag]++
		}
	}

	writeTagDistribution(b, "自己的發佈主題分佈：\n", ownTags)
	writeTagDistribution(b, "\nRSS 高分文章主題分佈：\n", rssTags)

	var gaps []string
	for _, tag := range slices.Sorted(maps.Keys(rssTags)) {
		if ownTags[tag] == 0 {
			gaps = append(gaps, tag)
		}
	}
	if len(gaps) > 0 {
		b.WriteString("\n潛在缺口（RSS 熱門但自己未涉獵）：\n")
		for _, tag := range gaps {
			fmt.Fprintf(b, "- %s（RSS 出現 %d 次）\n", tag, rssTags[tag])
		}
	}
}

func writeTagDistribution(b *strings.Builder, header string, tags map[string]int) {
	b.WriteString(header)
	if len(tags) == 0 {
		b.WriteString("（無標籤資料）\n")
		return
	}
	for _, tag := range slices.Sorted(maps.Keys(tags)) {
		fmt.Fprintf(b, "- %s: %d 篇\n", tag, tags[tag])
	}
}

// mock constructor moved to mock.go
