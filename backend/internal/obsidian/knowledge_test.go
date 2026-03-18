package obsidian

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseKnowledge(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     *Knowledge
		wantBody string
		wantErr  bool
	}{
		{
			name: "direct type field",
			input: `---
title: "Two Sum"
type: leetcode
source: leetcode
context: leetcode
difficulty: easy
leetcode_id: 1
tags:
  - array
  - hash-table
created: 2026-03-01
updated: 2026-03-01
---

# Two Sum

Use a hash map.`,
			want: &Knowledge{
				Title:      "Two Sum",
				Type:       "leetcode",
				Source:     "leetcode",
				Context:    "leetcode",
				Difficulty: "easy",
				LeetcodeID: 1,
				Tags:       []string{"array", "hash-table"},
				Created:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
				Updated:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "# Two Sum\n\nUse a hash map.",
		},
		{
			name: "fallback to type tag",
			input: `---
title: "DDIA Chapter 8"
tags:
  - type/book-note
  - distributed-systems
  - status/evergreen
book: "Designing Data-Intensive Applications"
chapter: "Chapter 8"
created: 2026-02-15
---

# DDIA Ch8 Notes`,
			want: &Knowledge{
				Title:   "DDIA Chapter 8",
				Type:    "book-note",
				Tags:    []string{"distributed-systems", "status/evergreen"},
				Book:    "Designing Data-Intensive Applications",
				Chapter: "Chapter 8",
				Created: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "# DDIA Ch8 Notes",
		},
		{
			name: "direct type removes type tags",
			input: `---
title: "Dev Log"
type: dev-log
tags:
  - type/dev-log
  - golang
---

Content here.`,
			want: &Knowledge{
				Title: "Dev Log",
				Type:  "dev-log",
				Tags:  []string{"golang"},
			},
			wantBody: "Content here.",
		},
		{
			name: "missing type entirely",
			input: `---
title: "No Type"
tags:
  - golang
  - concurrency
---

Some notes.`,
			want: &Knowledge{
				Title: "No Type",
				Type:  "",
				Tags:  []string{"golang", "concurrency"},
			},
			wantBody: "Some notes.",
		},
		{
			name: "all optional fields",
			input: `---
title: "Full Note"
type: learning-log
source: claude
context: koopa0dev
status: sapling
tags:
  - ai
  - genkit
difficulty: medium
leetcode_id: 42
book: "Go in Action"
chapter: "Chapter 5"
notion_task_id: abc-123
published: true
created: 2026-03-10
updated: 2026-03-12
---

Full body.`,
			want: &Knowledge{
				Title:        "Full Note",
				Type:         "learning-log",
				Source:       "claude",
				Context:      "koopa0dev",
				Status:       "sapling",
				Tags:         []string{"ai", "genkit"},
				Difficulty:   "medium",
				LeetcodeID:   42,
				Book:         "Go in Action",
				Chapter:      "Chapter 5",
				NotionTaskID: "abc-123",
				Published:    true,
				Created:      time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
				Updated:      time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC),
			},
			wantBody: "Full body.",
		},
		{
			name: "minimal frontmatter",
			input: `---
type: note
---

Just a note.`,
			want: &Knowledge{
				Type: "note",
				Tags: []string{},
			},
			wantBody: "Just a note.",
		},
		{
			name: "empty tags",
			input: `---
title: "Empty Tags"
type: til
tags: []
---

Body.`,
			want: &Knowledge{
				Title: "Empty Tags",
				Type:  "til",
				Tags:  []string{},
			},
			wantBody: "Body.",
		},
		{
			name:    "no frontmatter",
			input:   "# Just markdown\n\nNo frontmatter.",
			wantErr: true,
		},
		{
			name:    "unclosed frontmatter",
			input:   "---\ntitle: broken\n\nNo closing.",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, body, err := ParseKnowledge([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKnowledge() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseKnowledge() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantBody, body); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractTypeFromTags(t *testing.T) {
	tests := []struct {
		name          string
		tags          []string
		wantType      string
		wantRemaining []string
	}{
		{
			name:          "type tag present",
			tags:          []string{"type/article", "golang", "status/draft"},
			wantType:      "article",
			wantRemaining: []string{"golang", "status/draft"},
		},
		{
			name:          "no type tag",
			tags:          []string{"golang", "concurrency"},
			wantType:      "",
			wantRemaining: []string{"golang", "concurrency"},
		},
		{
			name:          "multiple type tags uses first",
			tags:          []string{"type/til", "type/note"},
			wantType:      "til",
			wantRemaining: []string{},
		},
		{
			name:          "empty tags",
			tags:          nil,
			wantType:      "",
			wantRemaining: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotRemaining := extractTypeFromTags(tt.tags)
			if gotType != tt.wantType {
				t.Errorf("extractTypeFromTags() type = %q, want %q", gotType, tt.wantType)
			}
			if diff := cmp.Diff(tt.wantRemaining, gotRemaining); diff != "" {
				t.Errorf("extractTypeFromTags() remaining mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
