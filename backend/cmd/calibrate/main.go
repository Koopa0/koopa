// Command calibrate runs the content-review AI flow against local Obsidian
// markdown files and prints a summary table for human evaluation.
// It bypasses Runner/DB — Genkit calls are made directly.
//
// Usage:
//
//	GEMINI_API_KEY=... go run ./cmd/calibrate [dir]
//
// Default dir: /Users/koopa/obsidian/10-Public-Content
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/content"
	aiflow "github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/obsidian"
	"github.com/koopa0/blog-backend/internal/topic"
)

const defaultDir = "/Users/koopa/obsidian/10-Public-Content"

// calibration topic slugs — hardcoded because we skip DB.
// These match the topics in the production database.
var calibrationTopics = []topic.Slug{
	{Slug: "golang", Name: "Go"},
	{Slug: "rust", Name: "Rust"},
	{Slug: "docker", Name: "Docker"},
	{Slug: "kubernetes", Name: "Kubernetes"},
	{Slug: "devops", Name: "DevOps"},
	{Slug: "architecture", Name: "Architecture"},
	{Slug: "database", Name: "Database"},
	{Slug: "frontend", Name: "Frontend"},
	{Slug: "ai", Name: "AI"},
	{Slug: "career", Name: "Career"},
}

// articleResult holds per-article AI output + metadata.
type articleResult struct {
	File        string                   `json:"file"`
	Title       string                   `json:"title"`
	ContentType string                   `json:"content_type"`
	Output      aiflow.ContentReviewOutput `json:"output"`
	DurationMS  int64                    `json:"duration_ms"`
	Error       string                   `json:"error,omitempty"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	dir := defaultDir
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		logger.Error("GEMINI_API_KEY is required")
		os.Exit(1)
	}

	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = "gemini-3-flash-preview"
	}

	if err := run(dir, model, logger); err != nil {
		logger.Error("calibration failed", "error", err)
		os.Exit(1)
	}
}

func run(dir, modelName string, logger *slog.Logger) error {
	ctx := context.Background()

	// Find markdown files
	pattern := filepath.Join(dir, "*.md")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("globbing %s: %w", pattern, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no markdown files found in %s", dir)
	}

	logger.Info("found articles", "count", len(files), "dir", dir)

	// Init Genkit + Gemini
	googleAI := &googlegenai.GoogleAI{}
	g := genkit.Init(ctx, genkit.WithPlugins(googleAI))

	gemini, err := googleAI.DefineModel(g, modelName, &ai.ModelOptions{
		Label: "Calibration",
		Supports: &ai.ModelSupports{
			Multiturn:  true,
			SystemRole: true,
			Media:      true,
		},
	})
	if err != nil {
		return fmt.Errorf("defining model %s: %w", modelName, err)
	}

	logger.Info("gemini model ready", "model", modelName)

	// Process each article
	results := make([]articleResult, 0, len(files))

	for _, file := range files {
		name := filepath.Base(file)
		logger.Info("processing", "file", name)

		result := processArticle(ctx, g, gemini, file, logger)
		results = append(results, result)

		if result.Error != "" {
			logger.Error("article failed", "file", name, "error", result.Error)
		} else {
			logger.Info("article done",
				"file", name,
				"level", result.Output.Proofread.Level,
				"duration_ms", result.DurationMS,
			)
		}
	}

	// Print markdown table to stdout
	printTable(results)

	// Write raw JSON to file
	jsonPath := filepath.Join(dir, "calibration-results.json")
	if err := writeJSON(jsonPath, results); err != nil {
		logger.Error("writing JSON results", "error", err)
	} else {
		fmt.Fprintf(os.Stderr, "\nRaw JSON written to %s\n", jsonPath)
	}

	return nil
}

func processArticle(ctx context.Context, g *genkit.Genkit, model ai.Model, file string, _ *slog.Logger) articleResult {
	name := filepath.Base(file)
	start := time.Now()

	raw, err := os.ReadFile(file) // #nosec G304 G703 -- CLI tool reads user-specified local files
	if err != nil {
		return articleResult{File: name, Error: fmt.Sprintf("reading file: %v", err)}
	}

	parsed, body, err := obsidian.Parse(raw)
	if err != nil {
		return articleResult{File: name, Error: fmt.Sprintf("parsing frontmatter: %v", err)}
	}

	// Build content.Content in-memory (no DB)
	c := &content.Content{
		Title: parsed.Title,
		Body:  body,
		Type:  content.Type(parsed.ContentType),
	}

	userPrompt := fmt.Sprintf("Type: %s\nTitle: %s\n\nBody:\n%s", c.Type, c.Title, c.Body)

	// Step 1: proofread (sequential — needed before parallel steps)
	reviewResult, err := runProofread(ctx, g, model, userPrompt)
	if err != nil {
		return articleResult{
			File:  name,
			Title: parsed.Title,
			Error: fmt.Sprintf("proofread: %v", err),
		}
	}

	// Steps 2-4 (sequential for simplicity in calibration — no errgroup needed)
	excerpt, err := runExcerpt(ctx, g, model, userPrompt)
	if err != nil {
		return articleResult{
			File:  name,
			Title: parsed.Title,
			Error: fmt.Sprintf("excerpt: %v", err),
		}
	}

	tags, err := runTags(ctx, g, model, userPrompt, calibrationTopics)
	if err != nil {
		return articleResult{
			File:  name,
			Title: parsed.Title,
			Error: fmt.Sprintf("tags: %v", err),
		}
	}

	readingTime := estimateReadingTime(body)

	elapsed := time.Since(start)

	return articleResult{
		File:        name,
		Title:       parsed.Title,
		ContentType: parsed.ContentType,
		Output: aiflow.ContentReviewOutput{
			Proofread:   reviewResult,
			Excerpt:     excerpt,
			Tags:        tags,
			ReadingTime: readingTime,
		},
		DurationMS: elapsed.Milliseconds(),
	}
}

func runProofread(ctx context.Context, g *genkit.Genkit, model ai.Model, userPrompt string) (*aiflow.ReviewResult, error) {
	result, _, err := genkit.GenerateData[aiflow.ReviewResult](ctx, g,
		ai.WithModel(model),
		ai.WithSystem(reviewSystemPrompt),
		ai.WithPrompt(userPrompt),
		ai.WithConfig(&genai.GenerateContentConfig{
			Temperature:     genai.Ptr[float32](0.3),
			MaxOutputTokens: 4096,
		}),
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func runExcerpt(ctx context.Context, g *genkit.Genkit, model ai.Model, userPrompt string) (string, error) {
	resp, err := genkit.Generate(ctx, g,
		ai.WithModel(model),
		ai.WithSystem(excerptSystemPrompt),
		ai.WithPrompt(userPrompt),
		ai.WithConfig(&genai.GenerateContentConfig{
			Temperature:     genai.Ptr[float32](0.5),
			MaxOutputTokens: 256,
		}),
	)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Text()), nil
}

func runTags(ctx context.Context, g *genkit.Genkit, model ai.Model, userPrompt string, topics []topic.Slug) ([]string, error) {
	var b strings.Builder
	b.WriteString("Existing tags:\n")
	for _, t := range topics {
		fmt.Fprintf(&b, "- %s (%s)\n", t.Slug, t.Name)
	}
	b.WriteString("\n")
	b.WriteString(userPrompt)

	resp, err := genkit.Generate(ctx, g,
		ai.WithModel(model),
		ai.WithSystem(tagsSystemPrompt),
		ai.WithPrompt(b.String()),
		ai.WithConfig(&genai.GenerateContentConfig{
			Temperature:     genai.Ptr[float32](0.2),
			MaxOutputTokens: 512,
		}),
	)
	if err != nil {
		return nil, err
	}

	var suggested []string
	if err := parseJSONLoose(resp.Text(), &suggested); err != nil {
		return nil, fmt.Errorf("parsing tags response: %w", err)
	}

	// Filter to only existing slugs
	existing := make(map[string]bool, len(topics))
	for _, s := range topics {
		existing[s.Slug] = true
	}
	var tags []string
	for _, tag := range suggested {
		if existing[tag] {
			tags = append(tags, tag)
		}
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, nil
}

func estimateReadingTime(body string) int {
	words := utf8.RuneCountInString(body) / 2
	if words == 0 {
		words = len(strings.Fields(body))
	}
	minutes := max(words/250, 1)
	return minutes
}

// parseJSONLoose extracts JSON from LLM output that may be wrapped in markdown.
func parseJSONLoose(text string, v any) error {
	text = strings.TrimSpace(text)

	if err := json.Unmarshal([]byte(text), v); err == nil {
		return nil
	}

	if _, after, ok := strings.Cut(text, "```json"); ok {
		rest := after
		if before, _, ok := strings.Cut(rest, "```"); ok {
			if err := json.Unmarshal([]byte(strings.TrimSpace(before)), v); err == nil {
				return nil
			}
		}
	}

	firstArr := strings.IndexByte(text, '[')
	lastArr := strings.LastIndexByte(text, ']')
	if firstArr >= 0 && lastArr > firstArr {
		if err := json.Unmarshal([]byte(text[firstArr:lastArr+1]), v); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no valid JSON found in response: %.100s", text)
}

// System prompts — re-read from embedded files via flow package exports would
// require exporting them, so we duplicate the references here for calibration.
// In production, these live in internal/flow/prompts/*.txt.
var (
	reviewSystemPrompt  string
	excerptSystemPrompt string
	tagsSystemPrompt    string
)

func init() {
	var err error
	reviewSystemPrompt, err = readPrompt("internal/flow/prompts/review.txt")
	if err != nil {
		panic(fmt.Sprintf("reading review prompt: %v", err))
	}
	excerptSystemPrompt, err = readPrompt("internal/flow/prompts/excerpt.txt")
	if err != nil {
		panic(fmt.Sprintf("reading excerpt prompt: %v", err))
	}
	tagsSystemPrompt, err = readPrompt("internal/flow/prompts/tags.txt")
	if err != nil {
		panic(fmt.Sprintf("reading tags prompt: %v", err))
	}
}

func readPrompt(relPath string) (string, error) {
	data, err := os.ReadFile(relPath) // #nosec G304 -- reads prompt files from known relative paths
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func printTable(results []articleResult) {
	// Header
	fmt.Println("# Calibration Results")
	fmt.Println()
	fmt.Println("| Title | Level | Excerpt | Tags | Reading Time | Corrections | Duration |")
	fmt.Println("|-------|-------|---------|------|-------------|-------------|----------|")

	for i := range results {
		r := results[i]
		if r.Error != "" {
			fmt.Printf("| %s | ERROR | %s | - | - | - | - |\n", truncate(r.Title, 40), truncate(r.Error, 50))
			continue
		}

		level := r.Output.Proofread.Level
		excerpt := truncate(r.Output.Excerpt, 60)
		tags := strings.Join(r.Output.Tags, ", ")
		if tags == "" {
			tags = "-"
		}
		rt := fmt.Sprintf("%d min", r.Output.ReadingTime)
		corrections := fmt.Sprintf("%d", len(r.Output.Proofread.Corrections))
		duration := fmt.Sprintf("%.1fs", float64(r.DurationMS)/1000)

		fmt.Printf("| %s | %s | %s | %s | %s | %s | %s |\n",
			truncate(r.Title, 40), level, excerpt, tags, rt, corrections, duration)
	}

	fmt.Println()

	// Print corrections detail for non-auto articles
	for i := range results {
		r := results[i]
		if r.Error != "" || r.Output.Proofread == nil {
			continue
		}
		if len(r.Output.Proofread.Corrections) > 0 || r.Output.Proofread.Level != "auto" {
			fmt.Printf("## %s\n\n", r.Title)
			fmt.Printf("**Level**: %s\n", r.Output.Proofread.Level)
			fmt.Printf("**Notes**: %s\n", r.Output.Proofread.Notes)
			if len(r.Output.Proofread.Corrections) > 0 {
				fmt.Println("**Corrections**:")
				for _, c := range r.Output.Proofread.Corrections {
					fmt.Printf("- %s\n", c)
				}
			}
			fmt.Println()
		}
	}
}

func writeJSON(path string, results []articleResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644) // #nosec G306 G703 -- calibration results are not sensitive
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "|", "\\|") // escape pipes for markdown table
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen-1]) + "…"
}
