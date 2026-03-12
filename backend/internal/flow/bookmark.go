package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/collected"
)

// BookmarkGenerateInput is the JSON input for the bookmark-generate flow.
type BookmarkGenerateInput struct {
	CollectedDataID string `json:"collected_data_id"`
}

// BookmarkResult is the structured output from the bookmark prompt.
type BookmarkResult struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

// BookmarkGenerateOutput is the JSON output of the bookmark-generate flow.
type BookmarkGenerateOutput struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

// BookmarkGenerate implements the bookmark-generate flow using Genkit.
type BookmarkGenerate struct {
	gf     *genkitFlow
	g      *genkit.Genkit
	model  ai.Model
	reader CollectedReader
	budget BudgetChecker
	logger *slog.Logger
}

// NewBookmarkGenerate returns a BookmarkGenerate flow.
func NewBookmarkGenerate(
	g *genkit.Genkit,
	model ai.Model,
	reader CollectedReader,
	budget BudgetChecker,
	logger *slog.Logger,
) *BookmarkGenerate {
	bg := &BookmarkGenerate{
		g:      g,
		model:  model,
		reader: reader,
		budget: budget,
		logger: logger,
	}
	bg.gf = genkit.DefineFlow(g, "bookmark-generate", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in BookmarkGenerateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing bookmark-generate input: %w", err)
		}
		out, err := bg.run(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return bg
}

// Name returns the flow name for registry lookup.
func (bg *BookmarkGenerate) Name() string { return "bookmark-generate" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (bg *BookmarkGenerate) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return bg.gf.Run(ctx, input)
}

const estimatedBookmarkTokens int64 = 2000

func (bg *BookmarkGenerate) run(ctx context.Context, in BookmarkGenerateInput) (BookmarkGenerateOutput, error) {
	id, err := uuid.Parse(in.CollectedDataID)
	if err != nil {
		return BookmarkGenerateOutput{}, fmt.Errorf("parsing collected data ID: %w", err)
	}

	if err := bg.budget.Check(estimatedBookmarkTokens); err != nil {
		return BookmarkGenerateOutput{}, fmt.Errorf("budget check: %w", err)
	}

	cd, err := genkit.Run(ctx, "fetch-collected", func() (*collected.CollectedData, error) {
		return bg.reader.CollectedDataByID(ctx, id)
	})
	if err != nil {
		return BookmarkGenerateOutput{}, fmt.Errorf("reading collected data %s: %w", id, err)
	}

	bg.logger.Info("bookmark-generate starting", "collected_id", id, "title", cd.Title)

	userPrompt := buildBookmarkUserPrompt(cd)

	result, err := genkit.Run(ctx, "generate-bookmark", func() (*BookmarkResult, error) {
		r, _, err := genkit.GenerateData[BookmarkResult](ctx, bg.g,
			ai.WithModel(bg.model),
			ai.WithSystem(bookmarkSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.5),
				MaxOutputTokens: 1024,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("generating bookmark: %w", err)
		}
		return r, nil
	})
	if err != nil {
		return BookmarkGenerateOutput{}, fmt.Errorf("generating bookmark for %s: %w", id, err)
	}

	bg.budget.Add(estimatedBookmarkTokens)

	bg.logger.Info("bookmark-generate complete", "collected_id", id, "title", result.Title)

	return BookmarkGenerateOutput{
		Title: result.Title,
		Body:  result.Body,
		Tags:  result.Tags,
	}, nil
}

// buildBookmarkUserPrompt assembles the user prompt for bookmark generation.
func buildBookmarkUserPrompt(cd *collected.CollectedData) string {
	title := cd.Title
	if cd.AITitleZH != nil {
		title = *cd.AITitleZH
	}
	summary := ""
	if cd.AISummaryZH != nil {
		summary = *cd.AISummaryZH
	}
	reason := ""
	if cd.AIScoreReason != nil {
		reason = *cd.AIScoreReason
	}

	return fmt.Sprintf("標題：%s\n來源：%s\nURL：%s\nAI 摘要：%s\n評分理由：%s",
		title, cd.SourceName, cd.SourceURL, summary, reason)
}

// NewMockBookmarkGenerate returns a mock Flow for MOCK_MODE.
func NewMockBookmarkGenerate() Flow {
	return &mockBookmarkFlow{}
}

type mockBookmarkFlow struct{}

func (m *mockBookmarkFlow) Name() string { return "bookmark-generate" }

func (m *mockBookmarkFlow) Run(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	out := BookmarkGenerateOutput{
		Title: "模擬書籤標題",
		Body:  "這是一個模擬的書籤推薦內容。",
		Tags:  []string{"mock"},
	}
	return json.Marshal(out)
}
