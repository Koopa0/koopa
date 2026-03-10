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

// BudgetChecker checks whether token usage is within budget.
type BudgetChecker interface {
	Check(tokens int64) error
	Add(tokens int64)
}

// CollectedReader reads collected data by ID.
type CollectedReader interface {
	CollectedDataByID(ctx context.Context, id uuid.UUID) (*collected.CollectedData, error)
}

// ScoringUpdater updates AI scoring fields on collected data.
type ScoringUpdater interface {
	UpdateScoring(ctx context.Context, id uuid.UUID, p collected.ScoringParams) error
}

// CollectScoreInput is the JSON input for the collect-and-score flow.
type CollectScoreInput struct {
	CollectedDataID string `json:"collected_data_id"`
}

// CollectScoreOutput is the JSON output of the collect-and-score flow.
type CollectScoreOutput struct {
	Score     int16  `json:"score"`
	Reason    string `json:"reason"`
	SummaryZH string `json:"summary_zh"`
	TitleZH   string `json:"title_zh"`
	Status    string `json:"status"`
}

// ScoreResult is the structured output from the scoring prompt.
type ScoreResult struct {
	Relevance int    `json:"relevance"`
	Depth     int    `json:"depth"`
	Freshness int    `json:"freshness"`
	Quality   int    `json:"quality"`
	Reason    string `json:"reason"`
	SummaryZH string `json:"summary_zh"`
	TitleZH   string `json:"title_zh"`
}

// WeightedScore computes the weighted average score.
func (s ScoreResult) WeightedScore() int16 {
	// relevance×0.35 + depth×0.30 + freshness×0.15 + quality×0.20
	score := float64(s.Relevance)*0.35 +
		float64(s.Depth)*0.30 +
		float64(s.Freshness)*0.15 +
		float64(s.Quality)*0.20
	// Scale 1-10 to 0-100
	return int16(score * 10)
}

// StatusFromScore returns the collected data status based on score thresholds.
func StatusFromScore(score int16) collected.Status {
	switch {
	case score >= 70:
		return collected.StatusCurated
	case score >= 50:
		return collected.StatusRead
	default:
		return collected.StatusIgnored
	}
}

// CollectScore implements the collect-and-score flow using Genkit.
type CollectScore struct {
	g       *genkit.Genkit
	model   ai.Model
	reader  CollectedReader
	updater ScoringUpdater
	budget  BudgetChecker
	logger  *slog.Logger
}

// NewCollectScore returns a CollectScore flow.
func NewCollectScore(
	g *genkit.Genkit,
	model ai.Model,
	reader CollectedReader,
	updater ScoringUpdater,
	budget BudgetChecker,
	logger *slog.Logger,
) *CollectScore {
	return &CollectScore{
		g:       g,
		model:   model,
		reader:  reader,
		updater: updater,
		budget:  budget,
		logger:  logger,
	}
}

// Name returns the flow name for registry lookup.
func (cs *CollectScore) Name() string { return "collect-and-score" }

// Run implements Flow.Run.
func (cs *CollectScore) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	var in CollectScoreInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("parsing collect-and-score input: %w", err)
	}
	out, err := cs.run(ctx, in)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// estimatedScoreTokens is a rough estimate of tokens for scoring one article.
const estimatedScoreTokens int64 = 2000

func (cs *CollectScore) run(ctx context.Context, in CollectScoreInput) (CollectScoreOutput, error) {
	id, err := uuid.Parse(in.CollectedDataID)
	if err != nil {
		return CollectScoreOutput{}, fmt.Errorf("parsing collected data ID: %w", err)
	}

	// Check budget before calling LLM
	if err := cs.budget.Check(estimatedScoreTokens); err != nil {
		return CollectScoreOutput{}, fmt.Errorf("budget check: %w", err)
	}

	cd, err := genkit.Run(ctx, "fetch-collected", func() (*collected.CollectedData, error) {
		return cs.reader.CollectedDataByID(ctx, id)
	})
	if err != nil {
		return CollectScoreOutput{}, fmt.Errorf("reading collected data %s: %w", id, err)
	}

	cs.logger.Info("collect-and-score starting", "collected_id", id, "title", cd.Title)

	userPrompt := buildScoreUserPrompt(cd)

	result, err := genkit.Run(ctx, "score", func() (*ScoreResult, error) {
		r, _, err := genkit.GenerateData[ScoreResult](ctx, cs.g,
			ai.WithModel(cs.model),
			ai.WithSystem(scoreSystemPrompt),
			ai.WithPrompt(userPrompt),
			ai.WithConfig(&genai.GenerateContentConfig{
				Temperature:     genai.Ptr[float32](0.3),
				MaxOutputTokens: 1024,
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("generating score: %w", err)
		}
		return r, nil
	})
	if err != nil {
		return CollectScoreOutput{}, fmt.Errorf("scoring collected data %s: %w", id, err)
	}

	cs.budget.Add(estimatedScoreTokens)

	score := result.WeightedScore()
	status := StatusFromScore(score)

	// Update collected data with scoring results
	if err := cs.updater.UpdateScoring(ctx, id, collected.ScoringParams{
		Score:     score,
		Reason:    result.Reason,
		SummaryZH: result.SummaryZH,
		TitleZH:   result.TitleZH,
		Status:    status,
	}); err != nil {
		return CollectScoreOutput{}, fmt.Errorf("updating scoring for %s: %w", id, err)
	}

	cs.logger.Info("collect-and-score complete",
		"collected_id", id,
		"score", score,
		"status", status,
		"relevance", result.Relevance,
		"depth", result.Depth,
	)

	return CollectScoreOutput{
		Score:     score,
		Reason:    result.Reason,
		SummaryZH: result.SummaryZH,
		TitleZH:   result.TitleZH,
		Status:    string(status),
	}, nil
}

// buildScoreUserPrompt assembles the user prompt for scoring.
func buildScoreUserPrompt(cd *collected.CollectedData) string {
	content := ""
	if cd.OriginalContent != nil {
		content = *cd.OriginalContent
	}
	return fmt.Sprintf("Title: %s\nSource: %s\nURL: %s\n\nContent:\n%s",
		cd.Title, cd.SourceName, cd.SourceURL, content)
}

// NewMockCollectScore returns a mock Flow for MOCK_MODE.
func NewMockCollectScore() Flow {
	return &mockCollectScoreFlow{}
}

type mockCollectScoreFlow struct{}

func (m *mockCollectScoreFlow) Name() string { return "collect-and-score" }

func (m *mockCollectScoreFlow) Run(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	out := CollectScoreOutput{
		Score:     75,
		Reason:    "Mock scoring result.",
		SummaryZH: "模擬摘要。",
		TitleZH:   "模擬標題",
		Status:    string(collected.StatusCurated),
	}
	return json.Marshal(out)
}
