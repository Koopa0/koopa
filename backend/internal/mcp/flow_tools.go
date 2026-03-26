package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/content"
)

// --- invoke_content_polish ---

// InvokeContentPolishInput is the input for the invoke_content_polish tool.
type InvokeContentPolishInput struct {
	ContentID string `json:"content_id" jsonschema_description:"content UUID (required)"`
}

// InvokeContentPolishOutput is the output for the invoke_content_polish tool.
type InvokeContentPolishOutput struct {
	ContentID string `json:"content_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

func (s *Server) invokeContentPolish(ctx context.Context, _ *mcp.CallToolRequest, input InvokeContentPolishInput) (*mcp.CallToolResult, InvokeContentPolishOutput, error) {
	if input.ContentID == "" {
		return nil, InvokeContentPolishOutput{}, fmt.Errorf("content_id is required")
	}

	contentID, err := uuid.Parse(input.ContentID)
	if err != nil {
		return nil, InvokeContentPolishOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	// Verify content exists before submitting.
	if _, checkErr := s.contents.Content(ctx, contentID); checkErr != nil {
		if isNotFound(checkErr) {
			return nil, InvokeContentPolishOutput{}, fmt.Errorf("content %q not found", input.ContentID)
		}
		return nil, InvokeContentPolishOutput{}, fmt.Errorf("checking content: %w", checkErr)
	}

	status, err := s.flowInvoker.InvokePolish(ctx, input.ContentID)
	if err != nil {
		return nil, InvokeContentPolishOutput{}, fmt.Errorf("invoking content-polish: %w", err)
	}

	return nil, InvokeContentPolishOutput{
		ContentID: input.ContentID,
		Status:    status,
		Message:   "content-polish flow submitted; check flow run status for results",
	}, nil
}

// --- invoke_content_strategy ---

// InvokeContentStrategyInput is the input for the invoke_content_strategy tool.
type InvokeContentStrategyInput struct{}

// InvokeContentStrategyOutput is the output for the invoke_content_strategy tool.
type InvokeContentStrategyOutput struct {
	Text string `json:"text"`
}

func (s *Server) invokeContentStrategy(ctx context.Context, _ *mcp.CallToolRequest, _ InvokeContentStrategyInput) (*mcp.CallToolResult, InvokeContentStrategyOutput, error) {
	text, err := s.flowInvoker.InvokeStrategy(ctx)
	if err != nil {
		return nil, InvokeContentStrategyOutput{}, fmt.Errorf("invoking content-strategy: %w", err)
	}

	return nil, InvokeContentStrategyOutput{Text: text}, nil
}

// --- generate_social_excerpt ---

// SocialExcerptInput is the input for the generate_social_excerpt tool.
type SocialExcerptInput struct {
	ContentID string `json:"content_id,omitempty" jsonschema_description:"content UUID"`
	Slug      string `json:"slug,omitempty" jsonschema_description:"content slug (alternative to content_id)"`
	Platform  string `json:"platform" jsonschema_description:"linkedin|twitter (required)"`
}

// SocialExcerptOutput is the output for the generate_social_excerpt tool.
type SocialExcerptOutput struct {
	Excerpt  string   `json:"excerpt"`
	Hook     string   `json:"hook"`
	CTA      string   `json:"cta"`
	Hashtags []string `json:"hashtags"`
	Platform string   `json:"platform"`
}

// Platform-specific character limits.
const (
	twitterCharLimit  = 280
	linkedinCharLimit = 500
)

func (s *Server) generateSocialExcerpt(ctx context.Context, _ *mcp.CallToolRequest, input SocialExcerptInput) (*mcp.CallToolResult, SocialExcerptOutput, error) {
	switch input.Platform {
	case "twitter", "linkedin":
		// valid
	case "":
		return nil, SocialExcerptOutput{}, fmt.Errorf("platform is required: valid values are twitter, linkedin")
	default:
		return nil, SocialExcerptOutput{}, fmt.Errorf("invalid platform %q: valid values are twitter, linkedin", input.Platform)
	}

	c, err := s.resolveContent(ctx, input.ContentID, input.Slug)
	if err != nil {
		return nil, SocialExcerptOutput{}, err
	}

	hook := extractFirstSentence(c.Body)
	charLimit := linkedinCharLimit
	if input.Platform == "twitter" {
		charLimit = twitterCharLimit
	}
	excerpt := truncateToCharLimit(c.Body, charLimit)
	cta := fmt.Sprintf("Read the full article at koopa0.dev/blog/%s", c.Slug)
	hashtags := tagsToHashtags(c.Tags)

	return nil, SocialExcerptOutput{
		Excerpt:  excerpt,
		Hook:     hook,
		CTA:      cta,
		Hashtags: hashtags,
		Platform: input.Platform,
	}, nil
}

// resolveContent looks up content by ID or slug.
func (s *Server) resolveContent(ctx context.Context, contentID, slug string) (*content.Content, error) {
	if contentID != "" {
		id, err := uuid.Parse(contentID)
		if err != nil {
			return nil, fmt.Errorf("invalid content_id: %w", err)
		}
		c, err := s.contents.Content(ctx, id)
		if err != nil {
			if isNotFound(err) {
				return nil, fmt.Errorf("content %q not found", contentID)
			}
			return nil, fmt.Errorf("querying content: %w", err)
		}
		return c, nil
	}
	if slug != "" {
		c, err := s.contents.ContentBySlug(ctx, slug)
		if err != nil {
			if isNotFound(err) {
				return nil, fmt.Errorf("content %q not found", slug)
			}
			return nil, fmt.Errorf("querying content: %w", err)
		}
		return c, nil
	}
	return nil, fmt.Errorf("either content_id or slug is required")
}

// isNotFound checks if err wraps content.ErrNotFound.
func isNotFound(err error) bool {
	return errors.Is(err, content.ErrNotFound)
}

// extractFirstSentence returns the first sentence of the text body.
// Falls back to the first 100 runes if no sentence-ending punctuation is found.
func extractFirstSentence(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}

	// Strip leading markdown headings.
	for strings.HasPrefix(body, "#") {
		if idx := strings.IndexByte(body, '\n'); idx >= 0 {
			body = strings.TrimSpace(body[idx+1:])
		} else {
			break
		}
	}

	// Find first sentence-ending punctuation.
	for i, r := range body {
		if r == '.' || r == '!' || r == '?' || r == '。' || r == '！' || r == '？' {
			return body[:i+utf8.RuneLen(r)]
		}
		// Stop at paragraph break.
		if r == '\n' && i > 0 {
			return strings.TrimSpace(body[:i])
		}
	}

	// Fallback: truncate at 100 runes.
	runes := []rune(body)
	if len(runes) > 100 {
		return string(runes[:100]) + "..."
	}
	return body
}

// truncateToCharLimit truncates body to the given rune limit, breaking at word boundary.
func truncateToCharLimit(body string, limit int) string {
	body = strings.TrimSpace(body)

	// Strip leading markdown headings.
	for strings.HasPrefix(body, "#") {
		if idx := strings.IndexByte(body, '\n'); idx >= 0 {
			body = strings.TrimSpace(body[idx+1:])
		} else {
			break
		}
	}

	runes := []rune(body)
	if len(runes) <= limit {
		return body
	}

	// Find last space before the limit to break at word boundary.
	truncated := string(runes[:limit])
	if lastSpace := strings.LastIndexByte(truncated, ' '); lastSpace > limit/2 {
		truncated = truncated[:lastSpace]
	}
	return truncated + "..."
}

// tagsToHashtags converts content tags to hashtag format.
func tagsToHashtags(tags []string) []string {
	if len(tags) == 0 {
		return []string{}
	}
	hashtags := make([]string, len(tags))
	for i, tag := range tags {
		// Replace hyphens and spaces with camelCase-like joining.
		cleaned := strings.ReplaceAll(tag, " ", "")
		cleaned = strings.ReplaceAll(cleaned, "-", "")
		hashtags[i] = "#" + cleaned
	}
	return hashtags
}
