package ai

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

	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/project"
)

// buildLogInput is the JSON input for the build-log-generate flow.
type buildLogInput struct {
	ProjectSlug string `json:"project_slug"`
	Days        int    `json:"days"` // lookback period, default 7
}

// buildLogLLMOutput is the structured output from the LLM.
type buildLogLLMOutput struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

// BuildLogOutput is the JSON output of the build-log-generate flow.
type BuildLogOutput struct {
	ContentID string `json:"content_id"`
	Title     string `json:"title"`
}

// BuildLog implements the build-log-generate flow.
type BuildLog struct {
	gf           *GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	projects     *project.Store
	commits      *github.Client
	content      *content.Store
	budget       *budget.Budget
	loc          *time.Location
	logger       *slog.Logger
}

// BuildLogDeps bundles dependencies for the BuildLog flow.
type BuildLogDeps struct {
	SystemPrompt string
	Projects     *project.Store
	Commits      *github.Client
	Content      *content.Store
	TokenBudget  *budget.Budget
	Location     *time.Location
	Logger       *slog.Logger
}

// NewBuildLog returns a BuildLog flow.
func NewBuildLog(g *genkit.Genkit, model genkitai.Model, deps BuildLogDeps) *BuildLog {
	bl := &BuildLog{
		g:            g,
		model:        model,
		systemPrompt: deps.SystemPrompt,
		projects:     deps.Projects,
		commits:      deps.Commits,
		content:      deps.Content,
		budget:       deps.TokenBudget,
		loc:          deps.Location,
		logger:       deps.Logger,
	}
	bl.gf = genkit.DefineFlow(g, "build-log-generate", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		out, err := bl.run(ctx, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return bl
}

// Name returns the flow name for registry lookup.
func (bl *BuildLog) Name() string { return "build-log-generate" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (bl *BuildLog) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return bl.gf.Run(ctx, input)
}

const estimatedBuildLogTokens int64 = 3000

func (bl *BuildLog) run(ctx context.Context, raw json.RawMessage) (BuildLogOutput, error) {
	var input buildLogInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return BuildLogOutput{}, fmt.Errorf("parsing build-log input: %w", err)
	}

	if input.ProjectSlug == "" {
		return BuildLogOutput{}, fmt.Errorf("project_slug is required")
	}
	if input.Days <= 0 {
		input.Days = 7
	}

	proj, err := bl.projects.ProjectBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return BuildLogOutput{}, fmt.Errorf("finding project %s: %w", input.ProjectSlug, err)
	}

	if proj.Repo == nil || *proj.Repo == "" {
		return BuildLogOutput{}, fmt.Errorf("project %s has no linked repo", input.ProjectSlug)
	}

	if reserveErr := bl.budget.Reserve(estimatedBuildLogTokens); reserveErr != nil {
		return BuildLogOutput{}, fmt.Errorf("budget reserve: %w", reserveErr)
	}

	bl.logger.Info("build-log-generate starting",
		"project", proj.Title,
		"repo", *proj.Repo,
		"days", input.Days,
	)

	now := time.Now().In(bl.loc)
	since := now.Add(-time.Duration(input.Days) * 24 * time.Hour)
	commits, err := bl.commits.CommitsForRepo(ctx, *proj.Repo, since)
	if err != nil {
		return BuildLogOutput{}, fmt.Errorf("fetching commits for %s: %w", *proj.Repo, err)
	}

	if len(commits) == 0 {
		return BuildLogOutput{}, fmt.Errorf("no commits found for %s in last %d days", *proj.Repo, input.Days)
	}

	userPrompt := buildBuildLogPrompt(proj, commits, input.Days)

	respText, err := genkit.Run(ctx, "generate-build-log", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, bl.g,
			genkitai.WithModel(bl.model),
			genkitai.WithSystem(bl.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 2048,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating build log: %w", genErr)
		}
		if finishErr := CheckFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return BuildLogOutput{}, err
	}

	var llmOut buildLogLLMOutput
	if parseErr := ParseJSONLoose(respText, &llmOut); parseErr != nil {
		return BuildLogOutput{}, fmt.Errorf("parsing build-log LLM output: %w", parseErr)
	}

	// Generate slug from project slug + date
	slug := fmt.Sprintf("%s-build-log-%s", proj.Slug, now.Format("2006-01-02"))
	sourceType := content.SourceAIGenerated
	source := fmt.Sprintf("build-log-generate:%s", *proj.Repo)

	created, err := bl.content.CreateContent(ctx, &content.CreateParams{
		Slug:        slug,
		Title:       llmOut.Title,
		Body:        llmOut.Body,
		Type:        content.TypeBuildLog,
		Status:      content.StatusDraft,
		Tags:        llmOut.Tags,
		SourceType:  &sourceType,
		Source:      &source,
		ReviewLevel: content.ReviewLight,
	})
	if err != nil {
		return BuildLogOutput{}, fmt.Errorf("creating build-log content: %w", err)
	}

	bl.logger.Info("build-log-generate complete",
		"project", proj.Title,
		"content_id", created.ID,
		"title", llmOut.Title,
		"commits", len(commits),
	)

	return BuildLogOutput{
		ContentID: created.ID.String(),
		Title:     llmOut.Title,
	}, nil
}

func buildBuildLogPrompt(proj *project.Project, commits []github.Commit, days int) string {
	var b strings.Builder

	fmt.Fprintf(&b, "專案名稱：%s\n", proj.Title)
	fmt.Fprintf(&b, "專案描述：%s\n", proj.Description)
	if proj.LongDescription != nil && *proj.LongDescription != "" {
		fmt.Fprintf(&b, "目前進度：%s\n", *proj.LongDescription)
	}
	fmt.Fprintf(&b, "回顧天數：%d\n", days)

	b.WriteString("\n== Commits ==\n")
	for _, c := range commits {
		fmt.Fprintf(&b, "- %s %s (%s)\n", c.SHA, c.Message, c.Date.Format("2006-01-02"))
	}

	return b.String()
}
