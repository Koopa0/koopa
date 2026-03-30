// Package obsidian provides Markdown frontmatter parsing for Obsidian vault files.
package obsidian

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// frontmatter represents the raw YAML frontmatter from an Obsidian file.
type frontmatter struct {
	Title     string   `yaml:"title"`
	Tags      []string `yaml:"tags"`
	Published bool     `yaml:"published"`
	Created   string   `yaml:"created"`
	Updated   string   `yaml:"updated"`
}

// Parsed represents the result of parsing Obsidian frontmatter mapped to content fields.
type Parsed struct {
	Title       string
	ContentType string   // extracted from "type/*" tag (e.g., "article", "til")
	Tags        []string // remaining tags (not type/* or status/*)
	TopicSlugs  []string // first segment of hierarchical tags (e.g., "golang" from "golang/memory")
	Published   bool
	Created     time.Time
	Updated     time.Time
}

// Parse extracts YAML frontmatter from Markdown content and maps it to content fields.
// Returns the parsed result and the body (everything after frontmatter).
func Parse(raw []byte) (*Parsed, string, error) {
	fm, body, err := extractFrontmatter(raw)
	if err != nil {
		return nil, "", fmt.Errorf("extracting frontmatter: %w", err)
	}

	p := &Parsed{
		Title:     fm.Title,
		Published: fm.Published,
	}

	if fm.Created != "" {
		t, err := parseDate(fm.Created)
		if err != nil {
			return nil, "", fmt.Errorf("parsing created date: %w", err)
		}
		p.Created = t
	}

	if fm.Updated != "" {
		t, err := parseDate(fm.Updated)
		if err != nil {
			return nil, "", fmt.Errorf("parsing updated date: %w", err)
		}
		p.Updated = t
	}

	p.ContentType, p.Tags, p.TopicSlugs = classifyTags(fm.Tags)

	return p, body, nil
}

// extractFrontmatter splits YAML frontmatter from Markdown body.
func extractFrontmatter(raw []byte) (*frontmatter, string, error) {
	content := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(content, []byte("---")) {
		return nil, "", fmt.Errorf("no frontmatter delimiter found")
	}

	// find the closing ---
	rest := content[3:]
	before, after, ok := bytes.Cut(rest, []byte("\n---"))
	if !ok {
		return nil, "", fmt.Errorf("no closing frontmatter delimiter found")
	}

	yamlBlock := before
	body := string(after) // skip \n---

	var fm frontmatter
	if err := yaml.Unmarshal(yamlBlock, &fm); err != nil {
		return nil, "", fmt.Errorf("parsing yaml: %w", err)
	}

	return &fm, strings.TrimSpace(body), nil
}

// classifyTags separates tags into content type, remaining tags, and topic slugs.
//
// Rules:
//   - "type/article" → contentType = "article"
//   - "status/*" → ignored
//   - "golang/memory" → topicSlug = "golang", tag = "golang/memory"
//   - "docker" → tag = "docker" (no topic extraction for flat tags)
func classifyTags(tags []string) (contentType string, remaining, topicSlugs []string) {
	seen := make(map[string]bool)

	for _, tag := range tags {
		parts := strings.SplitN(tag, "/", 2)

		if len(parts) == 2 {
			prefix, value := parts[0], parts[1]

			switch prefix {
			case "type":
				contentType = value
				continue
			case "status":
				// ignored
				continue
			default:
				// hierarchical tag like "golang/memory"
				remaining = append(remaining, tag)
				if !seen[prefix] {
					topicSlugs = append(topicSlugs, prefix)
					seen[prefix] = true
				}
				continue
			}
		}

		// flat tag
		remaining = append(remaining, tag)
	}

	if remaining == nil {
		remaining = []string{}
	}
	if topicSlugs == nil {
		topicSlugs = []string{}
	}

	return contentType, remaining, topicSlugs
}

// parseDate parses a date string in YYYY-MM-DD format.
func parseDate(s string) (time.Time, error) {
	return time.Parse("2006-01-02", s)
}
