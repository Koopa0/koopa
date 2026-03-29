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
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/pipeline"
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

// Setup initializes the AI pipeline in either mock or real mode.
// It constructs all flows in the ai package, delegates report flow construction
// to the provided builder, and returns a registry + embedder for the wiring layer
// to create the runner and note embedder.
func Setup(
	ctx context.Context,
	cfg PipelineConfig,
	stores PipelineStores,
	github *pipeline.GitHub,
	notifier notify.Notifier,
	tokenBudget *budget.Budget,
	loc *time.Location,
	logger *slog.Logger,
	reportFlows ReportFlowBuilder,
) (*PipelineResult, error) {
	if cfg.MockMode {
		logger.Info("starting in MOCK MODE — AI calls disabled")
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

	// construct flows in the ai package
	contentProofread := NewProofread(g, geminiModel, ReviewSystemPrompt, logger)
	contentExcerpt := NewExcerpt(g, geminiModel, ExcerptSystemPrompt, logger)
	contentTags := NewTags(g, geminiModel, TagsSystemPrompt, logger)
	contentReview := NewContentReview(
		g, embedder,
		stores.Content, stores.Content, stores.Content, stores.Review, stores.Topic,
		contentProofread, contentExcerpt, contentTags,
		logger,
	)
	contentPolish := NewPolish(g, claudeModel, PolishSystemPrompt, stores.Content, logger)
	bookmarkGenerate := NewBookmarkGenerate(g, geminiModel, stores.Entry, tokenBudget, logger)
	projectTrack := NewProjectTrack(
		g, geminiModel, ProjectTrackSystemPrompt, stores.Project, stores.Project,
		notifier, tokenBudget, logger,
	)
	contentStrategy := NewContentStrategy(
		g, geminiModel, stores.Content, stores.Entry, stores.Project,
		notifier, tokenBudget, loc, logger,
	)
	buildLog := NewBuildLog(
		g, geminiModel, BuildLogSystemPrompt, stores.Project, github, stores.Content,
		tokenBudget, loc, logger,
	)

	// construct report sub-package flows via callback (avoids ai→ai/report cycle)
	reports := reportFlows(g, geminiModel)

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
