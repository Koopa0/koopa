package ai

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/anthropic"
	"github.com/firebase/genkit/go/plugins/googlegenai"

	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/topic"
)

// PipelineConfig holds parameters for AI pipeline setup.
type PipelineConfig struct {
	MockMode    bool
	GeminiModel string
	ClaudeModel string
}

// PipelineStores holds the store dependencies for AI flows.
// Concrete types for stores where no import cycle exists.
type PipelineStores struct {
	Content *content.Store
	Review  *review.Store
	Topic   *topic.Store
	Entry   *entry.Store
	Project *project.Store
}

// PipelineResult holds the outputs from AI pipeline setup.
type PipelineResult struct {
	Registry *Registry
	Embedder genkitai.Embedder // nil in mock mode
	Genkit   *genkit.Genkit    // nil in mock mode
}

// ReportFlowBuilder constructs report sub-package flows that the ai package
// cannot import directly (ai/report imports ai — reverse import would cycle).
// Called by Setup with the initialized Genkit instance and Gemini model.
// Returns flows for: digest, morning-brief, weekly-review, daily-dev-log.
type ReportFlowBuilder func(g *genkit.Genkit, model genkitai.Model) []Flow

// PipelineDeps bundles non-config, non-store dependencies for AI pipeline setup.
type PipelineDeps struct {
	GitHub      *github.Client
	Notifier    notify.Notifier
	TokenBudget *budget.Budget
	Location    *time.Location
	Logger      *slog.Logger
	ReportFlows ReportFlowBuilder
}

// Setup initializes the AI pipeline in either mock or real mode.
// It constructs all flows in the ai package, delegates report flow construction
// to the provided builder, and returns a registry + embedder for the wiring layer
// to create the runner and note embedder.
func Setup(
	ctx context.Context,
	cfg PipelineConfig,
	stores PipelineStores,
	deps PipelineDeps,
) (*PipelineResult, error) {
	if cfg.MockMode {
		deps.Logger.Info("starting in MOCK MODE — AI calls disabled")
		registry := NewRegistry(
			NewMockContentReview(),
			NewMockContentProofread(),
			NewMockContentExcerpt(),
			NewMockContentTags(),
			NewMockContentPolish(),
			NewMockDigestGenerate(),
			NewMockBookmarkGenerate(),
			NewMockMorningBrief(),
			NewMockWeeklyReview(),
			NewMockProjectTrack(),
			NewMockContentStrategy(),
			NewMockBuildLog(),
			NewMockDailyDevLog(),
		)
		return &PipelineResult{Registry: registry}, nil
	}

	googleAI := &googlegenai.GoogleAI{}
	anthropicPlugin := &anthropic.Anthropic{}
	g := genkit.Init(ctx, genkit.WithPlugins(googleAI, anthropicPlugin))

	geminiModel, err := googleAI.DefineModel(g, cfg.GeminiModel, &genkitai.ModelOptions{
		Label: "Gemini Review",
		Supports: &genkitai.ModelSupports{
			Multiturn:  true,
			SystemRole: true,
			Media:      true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("defining gemini model: %w", err)
	}

	claudeModel, err := anthropicPlugin.DefineModel(g, cfg.ClaudeModel, &genkitai.ModelOptions{
		Label: "Claude Polish",
		Supports: &genkitai.ModelSupports{
			Multiturn:  true,
			SystemRole: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("defining claude model: %w", err)
	}

	embedder, err := googleAI.DefineEmbedder(g, "gemini-embedding-2-preview", &genkitai.EmbedderOptions{})
	if err != nil {
		return nil, fmt.Errorf("defining embedder: %w", err)
	}

	// Construct flows in the ai package.
	// All flow constructors return concrete types (never error) — they register
	// a Genkit flow and store dependencies. No I/O or validation happens here.
	contentProofread := NewProofread(g, geminiModel, ReviewSystemPrompt, deps.Logger)
	contentExcerpt := NewExcerpt(g, geminiModel, ExcerptSystemPrompt, deps.Logger)
	contentTags := NewTags(g, geminiModel, TagsSystemPrompt, deps.Logger)
	contentReview := NewContentReview(g, ContentReviewDeps{
		Content:   stores.Content,
		Review:    stores.Review,
		Topics:    stores.Topic,
		Embedder:  embedder,
		Proofread: contentProofread,
		Excerpt:   contentExcerpt,
		Tags:      contentTags,
		Logger:    deps.Logger,
	})
	contentPolish := NewPolish(g, claudeModel, PolishSystemPrompt, stores.Content, deps.Logger)
	bookmarkGenerate := NewBookmarkGenerate(g, geminiModel, stores.Entry, deps.TokenBudget, deps.Logger)
	projectTrack := NewProjectTrack(g, geminiModel, ProjectTrackDeps{
		SystemPrompt: ProjectTrackSystemPrompt,
		Projects:     stores.Project,
		Notifier:     deps.Notifier,
		TokenBudget:  deps.TokenBudget,
		Logger:       deps.Logger,
	})
	contentStrategy := NewContentStrategy(g, geminiModel, ContentStrategyDeps{
		Contents:    stores.Content,
		Collected:   stores.Entry,
		Projects:    stores.Project,
		Notifier:    deps.Notifier,
		TokenBudget: deps.TokenBudget,
		Location:    deps.Location,
		Logger:      deps.Logger,
	})
	buildLog := NewBuildLog(g, geminiModel, BuildLogDeps{
		SystemPrompt: BuildLogSystemPrompt,
		Projects:     stores.Project,
		Commits:      deps.GitHub,
		Content:      stores.Content,
		TokenBudget:  deps.TokenBudget,
		Location:     deps.Location,
		Logger:       deps.Logger,
	})

	// construct report sub-package flows via callback (avoids ai→ai/report cycle)
	reports := deps.ReportFlows(g, geminiModel)

	allFlows := make([]Flow, 0, 9+len(reports))
	allFlows = append(allFlows,
		contentReview, contentProofread, contentExcerpt, contentTags,
		contentPolish, bookmarkGenerate,
		projectTrack, contentStrategy, buildLog,
	)
	allFlows = append(allFlows, reports...)

	registry := NewRegistry(allFlows...)
	return &PipelineResult{
		Registry: registry,
		Embedder: embedder,
		Genkit:   g,
	}, nil
}
