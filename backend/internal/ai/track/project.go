// Package track implements activity tracking AI flows.
package track

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/project"
)

// ProjectByRepoFinder finds a project by its GitHub repository name.
type ProjectByRepoFinder interface {
	ProjectByRepo(ctx context.Context, repo string) (*project.Project, error)
}

// ProjectDescriptionUpdater updates a project's long description.
type ProjectDescriptionUpdater interface {
	UpdateProject(ctx context.Context, id uuid.UUID, p *project.UpdateParams) (*project.Project, error)
}

// Sender sends a text notification.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// ProjectOutput is the JSON output of the project-track flow.
type ProjectOutput struct {
	Text    string `json:"text"`
	Skipped bool   `json:"skipped"`
}

// projectInput is the JSON input from the webhook handler.
type projectInput struct {
	Repo    string   `json:"repo"`
	Commits []string `json:"commits"`
}

// Project implements the project-track flow.
type Project struct {
	gf           *ai.GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	projects     ProjectByRepoFinder
	updater      ProjectDescriptionUpdater
	notifier     Sender
	budget       ai.BudgetChecker
	logger       *slog.Logger
}

// NewProject returns a Project flow.
func NewProject(
	g *genkit.Genkit,
	model genkitai.Model,
	systemPrompt string,
	projects ProjectByRepoFinder,
	updater ProjectDescriptionUpdater,
	notifier Sender,
	budget ai.BudgetChecker,
	logger *slog.Logger,
) *Project {
	pt := &Project{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		projects:     projects,
		updater:      updater,
		notifier:     notifier,
		budget:       budget,
		logger:       logger,
	}
	pt.gf = genkit.DefineFlow(g, "project-track", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		out, err := pt.run(ctx, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return pt
}

// Name returns the flow name for registry lookup.
func (pt *Project) Name() string { return "project-track" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (pt *Project) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return pt.gf.Run(ctx, input)
}

const estimatedTrackTokens int64 = 1000

func (pt *Project) run(ctx context.Context, raw json.RawMessage) (ProjectOutput, error) {
	var input projectInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return ProjectOutput{}, fmt.Errorf("parsing project-track input: %w", err)
	}

	if input.Repo == "" || len(input.Commits) == 0 {
		return ProjectOutput{Skipped: true, Text: "no repo or commits"}, nil
	}

	// Look up project by repo — if not found, skip silently
	proj, err := pt.projects.ProjectByRepo(ctx, input.Repo)
	if err != nil {
		pt.logger.Info("project-track: no project for repo, skipping", "repo", input.Repo)
		return ProjectOutput{Skipped: true, Text: "project not found for repo"}, nil
	}

	if reserveErr := pt.budget.Reserve(estimatedTrackTokens); reserveErr != nil {
		return ProjectOutput{}, fmt.Errorf("budget reserve: %w", reserveErr)
	}

	pt.logger.Info("project-track starting", "repo", input.Repo, "project", proj.Title, "commits", len(input.Commits))

	userPrompt := buildProjectPrompt(proj, input.Commits)

	text, err := genkit.Run(ctx, "generate-project-track", func() (string, error) {
		resp, genErr := genkit.Generate(ctx, pt.g,
			genkitai.WithModel(pt.model),
			genkitai.WithSystem(pt.systemPrompt),
			genkitai.WithPrompt(userPrompt),
			genkitai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 512,
			}),
		)
		if genErr != nil {
			return "", fmt.Errorf("generating project track: %w", genErr)
		}
		if finishErr := ai.CheckFinishReason(resp); finishErr != nil {
			return "", finishErr
		}
		return strings.TrimSpace(resp.Text()), nil
	})
	if err != nil {
		return ProjectOutput{}, err
	}

	// Update project's long description with the progress update
	_, err = pt.updater.UpdateProject(ctx, proj.ID, &project.UpdateParams{
		LongDescription: &text,
	})
	if err != nil {
		return ProjectOutput{}, fmt.Errorf("updating project description: %w", err)
	}

	// Send notification
	notifyText := fmt.Sprintf("[Project Track] %s\n%s", proj.Title, text)
	if err := pt.notifier.Send(ctx, notifyText); err != nil {
		pt.logger.Error("sending project-track notification", "error", err)
	}

	pt.logger.Info("project-track complete", "repo", input.Repo, "project", proj.Title)

	return ProjectOutput{Text: text}, nil
}

func buildProjectPrompt(proj *project.Project, commits []string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "專案名稱：%s\n", proj.Title)
	fmt.Fprintf(&b, "專案描述：%s\n", proj.Description)
	if proj.LongDescription != nil && *proj.LongDescription != "" {
		fmt.Fprintf(&b, "目前進度：%s\n", *proj.LongDescription)
	}

	b.WriteString("\n== 最新 Commits ==\n")
	for _, msg := range commits {
		fmt.Fprintf(&b, "- %s\n", msg)
	}

	return b.String()
}
