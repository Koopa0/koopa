package obsidian

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// knowledgeFrontmatter represents the raw YAML frontmatter from an Obsidian knowledge note.
// Supports all fields needed by the obsidian_notes table.
type knowledgeFrontmatter struct {
	Title        string   `yaml:"title"`
	Type         string   `yaml:"type"`
	Source       string   `yaml:"source"`
	Context      string   `yaml:"context"`
	Status       string   `yaml:"status"`
	Tags         []string `yaml:"tags"`
	Difficulty   string   `yaml:"difficulty"`
	LeetcodeID   int      `yaml:"leetcode_id"`
	Book         string   `yaml:"book"`
	Chapter      string   `yaml:"chapter"`
	NotionTaskID string   `yaml:"notion_task_id"`
	Published    bool     `yaml:"published"`
	Created      string   `yaml:"created"`
	Updated      string   `yaml:"updated"`
}

// Knowledge represents parsed Obsidian knowledge note metadata for the B1 pipeline.
type Knowledge struct {
	Title        string
	Type         string // hard required by B1 — caller must check
	Source       string
	Context      string
	Status       string
	Tags         []string // raw tags, not normalized
	Difficulty   string
	LeetcodeID   int
	Book         string
	Chapter      string
	NotionTaskID string
	Published    bool
	Created      time.Time
	Updated      time.Time
}

// ParseKnowledge extracts YAML frontmatter from Markdown content for the B1 (knowledge notes) pipeline.
// Returns the parsed knowledge metadata and the body (everything after frontmatter).
//
// Type resolution uses two stages:
//  1. Direct `type` field in frontmatter
//  2. Fallback: scan tags for "type/xxx" pattern (backward compat)
//
// If type is empty after both stages, Knowledge.Type is "" — the caller decides whether to skip.
func ParseKnowledge(raw []byte) (*Knowledge, string, error) {
	fmBytes, body, err := extractYAMLBlock(raw)
	if err != nil {
		return nil, "", fmt.Errorf("extracting frontmatter: %w", err)
	}

	var fm knowledgeFrontmatter
	if err := yaml.Unmarshal(fmBytes, &fm); err != nil {
		return nil, "", fmt.Errorf("parsing yaml: %w", err)
	}

	k := &Knowledge{
		Title:        fm.Title,
		Source:       fm.Source,
		Context:      fm.Context,
		Status:       fm.Status,
		Difficulty:   fm.Difficulty,
		LeetcodeID:   fm.LeetcodeID,
		Book:         fm.Book,
		Chapter:      fm.Chapter,
		NotionTaskID: fm.NotionTaskID,
		Published:    fm.Published,
	}

	// Type resolution: direct field first, then tag fallback.
	k.Type = fm.Type
	if k.Type == "" {
		k.Type, k.Tags = extractTypeFromTags(fm.Tags)
	} else {
		k.Tags = filterNonTypeTags(fm.Tags)
	}

	if fm.Created != "" {
		t, err := parseDate(fm.Created)
		if err != nil {
			return nil, "", fmt.Errorf("parsing created date: %w", err)
		}
		k.Created = t
	}

	if fm.Updated != "" {
		t, err := parseDate(fm.Updated)
		if err != nil {
			return nil, "", fmt.Errorf("parsing updated date: %w", err)
		}
		k.Updated = t
	}

	return k, body, nil
}

// extractYAMLBlock extracts the raw YAML bytes and body from Markdown content.
func extractYAMLBlock(raw []byte) ([]byte, string, error) {
	content := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(content, []byte("---")) {
		return nil, "", fmt.Errorf("no frontmatter delimiter found")
	}

	rest := content[3:]
	idx := bytes.Index(rest, []byte("\n---"))
	if idx < 0 {
		return nil, "", fmt.Errorf("no closing frontmatter delimiter found")
	}

	yamlBlock := rest[:idx]
	body := string(rest[idx+4:]) // skip \n---

	return yamlBlock, strings.TrimSpace(body), nil
}

// extractTypeFromTags scans tags for a "type/xxx" pattern, extracts the type,
// and returns remaining tags (excluding the matched type tag and status tags).
func extractTypeFromTags(tags []string) (string, []string) {
	var typ string
	var remaining []string

	for _, tag := range tags {
		parts := strings.SplitN(tag, "/", 2)
		if len(parts) == 2 && parts[0] == "type" {
			if typ == "" {
				typ = parts[1]
			}
			continue
		}
		remaining = append(remaining, tag)
	}

	if remaining == nil {
		remaining = []string{}
	}
	return typ, remaining
}

// filterNonTypeTags removes "type/*" tags from the list, keeping everything else.
func filterNonTypeTags(tags []string) []string {
	var remaining []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, "type/") {
			continue
		}
		remaining = append(remaining, tag)
	}
	if remaining == nil {
		remaining = []string{}
	}
	return remaining
}
