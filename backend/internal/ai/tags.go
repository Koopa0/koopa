package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"google.golang.org/genai"
)

// TagsInput is the JSON input for the content-tags sub-flow.
type TagsInput struct {
	ContentType string   `json:"content_type"`
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	TopicSlugs  []string `json:"topic_slugs"`
	TopicNames  []string `json:"topic_names"`
}

// TagsOutput is the JSON output of the content-tags sub-flow.
type TagsOutput struct {
	Tags []string `json:"tags"`
}

// Tags implements the content-tags sub-flow.
// It is pure: takes text + topic list as input, returns suggested tags, no DB access.
type Tags struct {
	gf           *GenkitFlow
	g            *genkit.Genkit
	model        genkitai.Model
	systemPrompt string
	logger       *slog.Logger
}

// NewTags returns a Tags flow.
func NewTags(g *genkit.Genkit, model genkitai.Model, systemPrompt string, logger *slog.Logger) *Tags {
	ct := &Tags{
		g:            g,
		model:        model,
		systemPrompt: systemPrompt,
		logger:       logger,
	}
	ct.gf = genkit.DefineFlow(g, "content-tags", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in TagsInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("parsing content-tags input: %w", err)
		}
		out, err := ct.run(ctx, &in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	return ct
}

// Name returns the flow name for registry lookup.
func (ct *Tags) Name() string { return "content-tags" }

// Run implements Flow.Run — delegates to the registered Genkit flow.
func (ct *Tags) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return ct.gf.Run(ctx, input)
}

// run is the typed internal implementation.
func (ct *Tags) run(ctx context.Context, in *TagsInput) (TagsOutput, error) {
	ct.logger.Info("content-tags starting", "title", in.Title)

	// Build topic list for the prompt.
	var topicList strings.Builder
	topicList.WriteString("Existing tags:\n")
	for i, slug := range in.TopicSlugs {
		name := slug
		if i < len(in.TopicNames) {
			name = in.TopicNames[i]
		}
		fmt.Fprintf(&topicList, "- %s (%s)\n", slug, name)
	}

	userPrompt := fmt.Sprintf("%s\nType: %s\nTitle: %s\n\nBody:\n%s",
		topicList.String(), in.ContentType, in.Title, TruncateBodyRunes(in.Body))

	tags, err := genkit.Run(ctx, "tags", func() ([]string, error) {
		const maxRetries = 2
		var suggested []string
		for attempt := range maxRetries {
			resp, err := genkit.Generate(ctx, ct.g,
				genkitai.WithModel(ct.model),
				genkitai.WithSystem(ct.systemPrompt),
				genkitai.WithPrompt(userPrompt),
				genkitai.WithConfig(&genai.GenerateContentConfig{
					Temperature:     genai.Ptr[float32](0.2),
					MaxOutputTokens: 512,
				}),
			)
			if err != nil {
				return nil, fmt.Errorf("calling llm: %w", err)
			}
			if err := CheckFinishReason(resp); err != nil {
				return nil, err
			}

			if err := ParseJSONLoose(resp.Text(), &suggested); err != nil {
				snippet := resp.Text()[:min(len(resp.Text()), 100)]
				if attempt < maxRetries-1 {
					ct.logger.Warn("content tags: JSON parse failed, retrying",
						"attempt", attempt+1, "error", err, "response", snippet)
					userPrompt = "Return ONLY a JSON array of tag slugs, no explanation. Example: [\"go\",\"testing\"]\n\n" + userPrompt
					continue
				}
				ct.logger.Warn("content tags: falling back to empty tags after retries",
					"error", err, "response", snippet)
				return []string{}, nil
			}
			break
		}

		// Filter to only existing slugs.
		existing := make(map[string]struct{}, len(in.TopicSlugs))
		for _, s := range in.TopicSlugs {
			existing[s] = struct{}{}
		}
		var filtered []string
		for _, tag := range suggested {
			if _, ok := existing[tag]; ok {
				filtered = append(filtered, tag)
			}
		}
		if len(filtered) == 0 && len(suggested) > 0 {
			ct.logger.Warn("all LLM-suggested tags rejected by allowlist",
				"title", in.Title, "suggested", suggested)
		}
		return filtered, nil
	})
	if err != nil {
		return TagsOutput{}, fmt.Errorf("generating tags: %w", err)
	}

	ct.logger.Info("content-tags complete", "title", in.Title, "count", len(tags))
	return TagsOutput{Tags: tags}, nil
}
