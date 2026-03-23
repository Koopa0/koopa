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
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
)

// PublishedContentLister lists published contents in a date range.
type PublishedContentLister interface {
	PublishedByDateRange(ctx context.Context, start, end time.Time) ([]content.Content, error)
}

// RecentCollectedLister lists recently collected data in a date range.
type RecentCollectedLister interface {
	RecentCollectedData(ctx context.Context, start, end time.Time, limit int32) ([]collected.Item, error)
}

// ActiveProjectLister lists active projects.
type ActiveProjectLister interface {
	ActiveProjects(ctx context.Context) ([]project.Project, error)
}

// DigestGenerateInput is the JSON input for the digest-generate flow.
type DigestGenerateInput struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD
	EndDate   string `json:"end_date"`   // YYYY-MM-DD
}

// DigestGenerateOutput is the JSON output of the digest-generate flow.
type DigestGenerateOutput struct {
	Markdown string `json:"markdown"`
}

// DigestGenerate implements the digest-generate flow using Genkit.
type DigestGenerate struct {
	gf       *genkitFlow
	g        *genkit.Genkit
	model    ai.Model
	contents PublishedContentLister
	collects RecentCollectedLister
	projects ActiveProjectLister
	budget   BudgetChecker
	loc      *time.Location
	logger   *slog.Logger
}

// NewDigestGenerate returns a DigestGenerate flow.
func NewDigestGenerate(
	g *genkit.Genkit,
	model ai.Model,
	contents PublishedContentLister,
	collects RecentCollectedLister,
	projects ActiveProjectLister,
	budget BudgetChecker,
	loc *time.Location,
	logger *slog.Logger,
) *DigestGenerate {
	dg := &DigestGenerate{
		g:        g,
		model:    model,
		contents: contents,
		collects: collects,
		projects: projects,
		budget:   budget,
		loc:      loc,
		logger:   logger,
	}
	dg.gf = genkit.DefineFlow(g, "digest-generate", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DigestGenerateInput
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
func (dg *DigestGenerate) Name() string { return "digest-generate" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (dg *DigestGenerate) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return dg.gf.Run(ctx, input)
}

const (
	estimatedDigestTokens int64 = 5000
	digestCollectedLimit  int32 = 50
)

func (dg *DigestGenerate) run(ctx context.Context, in DigestGenerateInput) (DigestGenerateOutput, error) {
	start, err := time.ParseInLocation("2006-01-02", in.StartDate, dg.loc)
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("parsing start date: %w", err)
	}
	end, err := time.ParseInLocation("2006-01-02", in.EndDate, dg.loc)
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("parsing end date: %w", err)
	}

	if reserveErr := dg.budget.Reserve(estimatedDigestTokens); reserveErr != nil {
		return DigestGenerateOutput{}, fmt.Errorf("budget reserve: %w", reserveErr)
	}

	dg.logger.Info("digest-generate starting", "start", in.StartDate, "end", in.EndDate)

	var (
		published      []content.Content
		highScoreItems []collected.Item
		activeProjects []project.Project
	)

	// Fetch published contents
	published, err = dg.contents.PublishedByDateRange(ctx, start, end)
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("listing published contents: %w", err)
	}

	// Fetch recent collected data
	highScoreItems, err = dg.collects.RecentCollectedData(ctx, start, end, digestCollectedLimit)
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("listing recent collected data: %w", err)
	}

	// Fetch active projects
	activeProjects, err = dg.projects.ActiveProjects(ctx)
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("listing active projects: %w", err)
	}

	userPrompt := buildDigestUserPrompt(published, highScoreItems, activeProjects, in.StartDate, in.EndDate)

	markdown, err := genkit.Run(ctx, "generate-digest", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, dg.g,
			ai.WithModel(dg.model),
			ai.WithSystem(digestSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.7),
				MaxOutputTokens: 4096,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating digest: %w", genErr)
		}
		if finishErr := checkFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return DigestGenerateOutput{}, fmt.Errorf("generating digest: %w", err)
	}

	dg.logger.Info("digest-generate complete",
		"published_count", len(published),
		"collected_count", len(highScoreItems),
		"project_count", len(activeProjects),
	)

	return DigestGenerateOutput{Markdown: markdown}, nil
}

// buildDigestUserPrompt assembles material for the digest prompt.
func buildDigestUserPrompt(
	published []content.Content,
	collectedData []collected.Item,
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

// NewMockDigestGenerate returns a mock Flow for MOCK_MODE.
func NewMockDigestGenerate() Flow {
	return &mockFlow{
		name:   "digest-generate",
		output: DigestGenerateOutput{Markdown: "## Mock Digest\n\nThis is a mock weekly digest."},
	}
}
