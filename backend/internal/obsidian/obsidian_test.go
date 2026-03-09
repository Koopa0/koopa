package obsidian

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantParsed *Parsed
		wantBody string
		wantErr  bool
	}{
		{
			name: "full blog draft",
			input: `---
title: "Go Escape Analysis 深入解析"
tags:
  - type/article
  - golang/memory
  - golang/compiler
  - status/draft
  - performance
published: true
created: 2026-03-09
updated: 2026-03-10
---

# Go Escape Analysis

This is the body.`,
			wantParsed: &Parsed{
				Title:       "Go Escape Analysis 深入解析",
				ContentType: "article",
				Tags:        []string{"golang/memory", "golang/compiler", "performance"},
				TopicSlugs:  []string{"golang"},
				Published:   true,
				Created:     time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC),
				Updated:     time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "# Go Escape Analysis\n\nThis is the body.",
		},
		{
			name: "unpublished note",
			input: `---
title: "Quick Note"
tags:
  - type/note
published: false
created: 2026-01-01
updated: 2026-01-01
---

Some note content.`,
			wantParsed: &Parsed{
				Title:       "Quick Note",
				ContentType: "note",
				Tags:        []string{},
				TopicSlugs:  []string{},
				Published:   false,
				Created:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Updated:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "Some note content.",
		},
		{
			name: "multiple topic slugs",
			input: `---
title: "Cross-topic"
tags:
  - type/til
  - golang/concurrency
  - system-design/distributed
  - docker
published: true
created: 2026-02-01
updated: 2026-02-01
---

Body here.`,
			wantParsed: &Parsed{
				Title:       "Cross-topic",
				ContentType: "til",
				Tags:        []string{"golang/concurrency", "system-design/distributed", "docker"},
				TopicSlugs:  []string{"golang", "system-design"},
				Published:   true,
				Created:     time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Updated:     time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "Body here.",
		},
		{
			name:    "no frontmatter",
			input:   "# Just a heading\n\nNo frontmatter here.",
			wantErr: true,
		},
		{
			name:    "unclosed frontmatter",
			input:   "---\ntitle: broken\n\nNo closing delimiter.",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, body, err := Parse([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.wantParsed, got); diff != "" {
				t.Errorf("Parsed mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantBody, body); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClassifyTags(t *testing.T) {
	tests := []struct {
		name        string
		tags        []string
		wantType    string
		wantTags    []string
		wantTopics  []string
	}{
		{
			name:       "mixed tags",
			tags:       []string{"type/article", "golang/memory", "status/evergreen", "docker"},
			wantType:   "article",
			wantTags:   []string{"golang/memory", "docker"},
			wantTopics: []string{"golang"},
		},
		{
			name:       "no type tag",
			tags:       []string{"golang/slice", "rust/ownership"},
			wantType:   "",
			wantTags:   []string{"golang/slice", "rust/ownership"},
			wantTopics: []string{"golang", "rust"},
		},
		{
			name:       "empty tags",
			tags:       nil,
			wantType:   "",
			wantTags:   []string{},
			wantTopics: []string{},
		},
		{
			name:       "dedup topic slugs",
			tags:       []string{"golang/memory", "golang/compiler", "golang/gc"},
			wantType:   "",
			wantTags:   []string{"golang/memory", "golang/compiler", "golang/gc"},
			wantTopics: []string{"golang"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotTags, gotTopics := classifyTags(tt.tags)
			if gotType != tt.wantType {
				t.Errorf("contentType = %q, want %q", gotType, tt.wantType)
			}
			if diff := cmp.Diff(tt.wantTags, gotTags); diff != "" {
				t.Errorf("tags mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantTopics, gotTopics); diff != "" {
				t.Errorf("topicSlugs mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
