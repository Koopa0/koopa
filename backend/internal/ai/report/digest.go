// Package report implements periodic report and summary AI flows.
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

	"github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/project"
)

// DigestInput is the JSON input for the digest-generate flow.
type DigestInput struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD
	EndDate   string `json:"end_date"`   // YYYY-MM-DD
}

// DigestOutput is the JSON output of the digest-generate flow.
type DigestOutput struct {
	Markdown string `json:"markdown"`
}

// Digest implements the digest-generate flow using Genkit.
type Digest struct {
	gf           *ai.GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	contents     *content.Store
	collects     *entry.Store
	projects     *project.Store
	budget       *budget.Budget
	loc          *time.Location
	logger       *slog.Logger
}

// NewDigest returns a Digest flow.
func NewDigest(
	g *genkit.Genkit,
	model genkitai.Model,
	systemPrompt string,
	contents *content.Store,
	collects *entry.Store,
	projects *project.Store,
	tokenBudget *budget.Budget,
	loc *time.Location,
	logger *slog.Logger,
) *Digest {
	dg := &Digest{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		contents:     contents,
		collects:     collects,
		projects:     projects,
		budget:       tokenBudget,
		loc:          loc,
		logger:       logger,
	}
	dg.gf = genkit.DefineFlow(g, "digest-generate", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DigestInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing digest-generate input: %w", err)
		}
		out, err := dg.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return dg
}

// Name returns the flow name for registry lookup.
func (dg *Digest) Name() string { return "digest-generate" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (dg *Digest) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return dg.gf.Run(ctx, input)
}

const (
	estimatedDigestTokens int64 = 5000
	digestCollectedLimit  int32 = 50
)

func (dg *Digest) run(ctx context.Context, in DigestInput) (DigestOutput, error) {
	start, err := time.ParseInLocation("2006-01-02", in.StartDate, dg.loc)
	if err != nil {
		return DigestOutput{}, fmt.Errorf("parsing start date: %w", err)
	}
	end, err := time.ParseInLocation("2006-01-02", in.EndDate, dg.loc)
	if err != nil {
		return DigestOutput{}, fmt.Errorf("parsing end date: %w", err)
	}

	if reserveErr := dg.budget.Reserve(estimatedDigestTokens); reserveErr != nil {
		return DigestOutput{}, fmt.Errorf("budget reserve: %w", reserveErr)
	}

	dg.logger.Info("digest-generate starting", "start", in.StartDate, "end", in.EndDate)

	var (
		published      []content.Content
		highScoreItems []entry.Item
		activeProjects []project.Project
	)

	// Fetch published contents
	published, err = dg.contents.PublishedByDateRange(ctx, start, end)
	if err != nil {
		return DigestOutput{}, fmt.Errorf("listing published contents: %w", err)
	}

	// Fetch recent collected data
	highScoreItems, err = dg.collects.RecentCollectedData(ctx, start, end, digestCollectedLimit)
	if err != nil {
		return DigestOutput{}, fmt.Errorf("listing recent collected data: %w", err)
	}

	// Fetch active projects
	activeProjects, err = dg.projects.ActiveProjects(ctx)
	if err != nil {
		return DigestOutput{}, fmt.Errorf("listing active projects: %w", err)
	}

	userPrompt := BuildDigestUserPrompt(published, highScoreItems, activeProjects, in.StartDate, in.EndDate)

	markdown, err := genkit.Run(ctx, "generate-digest", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, dg.g,
			genkitai.WithModel(dg.model),
			genkitai.WithSystem(dg.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.7),
				MaxOutputTokens: 4096,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating digest: %w", genErr)
		}
		if finishErr := ai.CheckFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return DigestOutput{}, fmt.Errorf("generating digest: %w", err)
	}

	dg.logger.Info("digest-generate complete",
		"published_count", len(published),
		"collected_count", len(highScoreItems),
		"project_count", len(activeProjects),
	)

	return DigestOutput{Markdown: markdown}, nil
}

// BuildDigestUserPrompt assembles material for the digest prompt.
// Exported for use by tests.
func BuildDigestUserPrompt(
	published []content.Content,
	collectedData []entry.Item,
	projects []project.Project,
	startDate, endDate string,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "期間：%s 至 %s\n\n", startDate, endDate)

	if len(published) > 0 {
		b.WriteString("## 本週發佈的內容\n\n")
		for i := range published {
			c := &published[i]
			fmt.Fprintf(&b, "- **%s** (%s)\n  摘要：%s\n\n", c.Title, c.Type, c.Excerpt)
		}
	}

	if len(collectedData) > 0 {
		b.WriteString("## 高評分收集文章\n\n")
		for i := range collectedData {
			cd := &collectedData[i]
			fmt.Fprintf(&b, "- **%s**\n  來源: %s\n  URL: %s\n\n",
				cd.Title, cd.SourceName, cd.SourceURL)
		}
	}

	if len(projects) > 0 {
		b.WriteString("## 活躍專案\n\n")
		for i := range projects {
			p := &projects[i]
			fmt.Fprintf(&b, "- **%s** (%s) — %s\n", p.Title, p.Status, p.Description)
		}
	}

	return b.String()
}
