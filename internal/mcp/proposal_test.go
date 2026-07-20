// Copyright 2026 Koopa. All rights reserved.

// proposal_test.go covers validateProposeContent (white-box, package mcp):
// every rejection branch named in the comment block in proposal.go, plus one
// accept case, plus a Fuzz for the slug-derivation + parseTopicIDs path.
package mcp

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestValidateProposeContent names the implementation bug each case would catch:
//
//   - "empty title"          → title check missing / swapped order
//   - "whitespace-only title" → TrimSpace absent on title check
//   - "empty type"           → type check missing
//   - "whitespace-only type"  → TrimSpace absent on type check
//   - "invalid type"         → contentType.Valid() not called
//   - "empty body"           → body check missing
//   - "whitespace-only body"  → TrimSpace absent on body check
//   - "control char in title" → ContainsControlChars not called on title
//   - "control char in body"  → containsProseControlChars not called on body
//   - "control char in excerpt" → ContainsControlChars not called on excerpt
//   - "control char in rationale" → ContainsControlChars not called on rationale
//   - "all-punctuation title → empty slug" → empty-slug guard missing
//   - "invalid topic UUID"   → parseTopicIDs not called
//   - "slug derived from title" → slug derivation logic removed
//   - "explicit slug passed through" → explicit-slug pass-through missing
//   - "accept valid input"    → any regression in the happy path
func TestValidateProposeContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		input           ProposeContentInput
		wantErr         bool
		wantErrContains string
		// When non-nil, assert the returned slug equals this string.
		wantSlug *string
		// When non-nil, assert the returned type equals this string.
		wantTypStr *string
	}{
		// ── required-field checks ──────────────────────────────────────────────
		{
			name:            "empty title",
			input:           ProposeContentInput{Title: "", Type: "article", Body: "body"},
			wantErr:         true,
			wantErrContains: "title is required",
		},
		{
			name:            "whitespace-only title",
			input:           ProposeContentInput{Title: "   ", Type: "article", Body: "body"},
			wantErr:         true,
			wantErrContains: "title is required",
		},
		{
			name:            "empty type",
			input:           ProposeContentInput{Title: "T", Type: "", Body: "body"},
			wantErr:         true,
			wantErrContains: "type is required",
		},
		{
			name:            "whitespace-only type",
			input:           ProposeContentInput{Title: "T", Type: "  ", Body: "body"},
			wantErr:         true,
			wantErrContains: "type is required",
		},
		{
			name:            "empty body",
			input:           ProposeContentInput{Title: "T", Type: "article", Body: ""},
			wantErr:         true,
			wantErrContains: "body is required",
		},
		{
			name:            "whitespace-only body",
			input:           ProposeContentInput{Title: "T", Type: "article", Body: "   "},
			wantErr:         true,
			wantErrContains: "body is required",
		},
		// ── content-type enum validation ───────────────────────────────────────
		{
			name:            "invalid type: podcast",
			input:           ProposeContentInput{Title: "T", Type: "podcast", Body: "body"},
			wantErr:         true,
			wantErrContains: "type must be one of",
		},
		{
			name:            "invalid type: uppercase Article",
			input:           ProposeContentInput{Title: "T", Type: "Article", Body: "body"},
			wantErr:         true,
			wantErrContains: "type must be one of",
		},
		// ── control-character rejection ────────────────────────────────────────
		{
			name:            "control char C0 in title",
			input:           ProposeContentInput{Title: "bad\x01title", Type: "article", Body: "body"},
			wantErr:         true,
			wantErrContains: "title must not contain control characters",
		},
		{
			// U+0080 is a C1 control rune. It must be written as string(rune(0x80)) (valid
			// UTF-8, 0xC2 0x80), not the raw byte \x80 — a raw 0x80 is invalid
			// UTF-8 and decodes to RuneError when ranged, never matching the
			// C1 range that ContainsControlChars checks.
			name:            "control char C1 in title",
			input:           ProposeContentInput{Title: "bad" + string(rune(0x80)) + "title", Type: "article", Body: "body"},
			wantErr:         true,
			wantErrContains: "title must not contain control characters",
		},
		{
			name: "control char C0 in body (not HT/LF/CR)",
			// \x01 is a C0 control char that prose-check rejects (not HT/LF/CR)
			input:           ProposeContentInput{Title: "T", Type: "article", Body: "bad\x01body"},
			wantErr:         true,
			wantErrContains: "body must not contain control characters",
		},
		{
			// Prose check must allow HT/LF/CR — rejecting LF would break a
			// multi-line Markdown body. Asserts a multi-line body is accepted.
			name:    "LF in body is allowed by prose check",
			input:   ProposeContentInput{Title: "T", Type: "til", Body: "line1\nline2"},
			wantErr: false,
		},
		{
			name:            "control char in excerpt",
			input:           ProposeContentInput{Title: "T", Type: "article", Body: "body", Excerpt: "ex\x01cerpt"},
			wantErr:         true,
			wantErrContains: "excerpt must not contain control characters",
		},
		{
			name:            "control char in proposal_rationale",
			input:           ProposeContentInput{Title: "T", Type: "article", Body: "body", ProposalRationale: "rat\x01ionale"},
			wantErr:         true,
			wantErrContains: "proposal_rationale must not contain control characters",
		},
		// ── slug derivation ────────────────────────────────────────────────────
		{
			name:            "all-punctuation title yields empty slug",
			input:           ProposeContentInput{Title: "!!!---", Type: "article", Body: "body"},
			wantErr:         true,
			wantErrContains: "must contain at least one letter or number",
		},
		{
			name: "slug derived from title when omitted",
			input: ProposeContentInput{
				Title: "Go Is Great",
				Type:  "article",
				Body:  "body",
			},
			wantErr:  false,
			wantSlug: ptr("go-is-great"),
		},
		{
			name: "explicit slug passes through unchanged",
			input: ProposeContentInput{
				Title: "Any Title",
				Type:  "essay",
				Body:  "body",
				Slug:  "my-custom-slug",
			},
			wantErr:  false,
			wantSlug: ptr("my-custom-slug"),
		},
		// ── topic UUID parsing ─────────────────────────────────────────────────
		{
			name: "invalid topic UUID",
			input: ProposeContentInput{
				Title:    "T",
				Type:     "article",
				Body:     "body",
				TopicIDs: []string{"not-a-uuid"},
			},
			wantErr:         true,
			wantErrContains: "not a valid uuid",
		},
		// ── accept cases ───────────────────────────────────────────────────────
		{
			name: "valid article",
			input: ProposeContentInput{
				Title:   "Understanding Interfaces in Go",
				Type:    "article",
				Body:    "Markdown body here.\n\n## Section\n\nContent.",
				Excerpt: "A short summary.",
			},
			wantErr:    false,
			wantTypStr: ptr("article"),
			wantSlug:   ptr("understanding-interfaces-in-go"),
		},
		{
			name: "valid til",
			input: ProposeContentInput{
				Title: "TIL: range over func",
				Type:  "til",
				Body:  "Go 1.23 adds range over func.\n",
			},
			wantErr:    false,
			wantTypStr: ptr("til"),
		},
		{
			name: "valid with topic UUIDs",
			input: ProposeContentInput{
				Title:    "T",
				Type:     "digest",
				Body:     "body",
				TopicIDs: []string{"550e8400-e29b-41d4-a716-446655440000"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !tt.wantErr {
				tt.input.SourceVaultPath = "Writing/articles/validation-fixture.md"
				tt.input.SourceGitBlobSHA = "0123456789abcdef0123456789abcdef01234567"
			}

			gotType, gotSlug, gotIDs, err := validateProposeContent(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateProposeContent() error = nil, want error containing %q", tt.wantErrContains)
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("validateProposeContent() error = %q, want containing %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateProposeContent() unexpected error: %v", err)
			}
			if tt.wantTypStr != nil && string(gotType) != *tt.wantTypStr {
				t.Errorf("validateProposeContent() type = %q, want %q", gotType, *tt.wantTypStr)
			}
			if tt.wantSlug != nil && gotSlug != *tt.wantSlug {
				t.Errorf("validateProposeContent() slug = %q, want %q", gotSlug, *tt.wantSlug)
			}
			// gotIDs may be nil or non-nil; just check it doesn't panic.
			_ = gotIDs
		})
	}
}

// ptr returns a pointer to the given string — helper for table fields.
func ptr(s string) *string { return &s }

// FuzzValidateProposeContent_SlugAndTopics fuzzes the slug-derivation +
// parseTopicIDs path. The seed corpus drives toward the cases most likely to
// panic: all-punctuation titles, malformed UUIDs, control characters.
func FuzzValidateProposeContent_SlugAndTopics(f *testing.F) {
	// Seed: valid
	f.Add("Go Interfaces", "article", "body", "", "")
	// Seed: all punctuation → empty slug
	f.Add("!!!---", "article", "body", "", "")
	// Seed: control chars
	f.Add("title\x01here", "article", "body", "", "")
	// Seed: invalid topic UUID
	f.Add("T", "article", "body", "", "not-a-uuid")
	// Seed: valid UUID
	f.Add("T", "article", "body", "", "550e8400-e29b-41d4-a716-446655440000")
	// Seed: empty
	f.Add("", "", "", "", "")
	// Seed: long title
	f.Add(strings.Repeat("x", 200), "article", "body", "", "")

	f.Fuzz(func(t *testing.T, title, typ, body, slug, topicID string) {
		var topicIDs []string
		if topicID != "" {
			topicIDs = []string{topicID}
		}
		input := ProposeContentInput{
			Title:    title,
			Type:     typ,
			Body:     body,
			Slug:     slug,
			TopicIDs: topicIDs,
		}
		// Must not panic on any input.
		_, _, _, _ = validateProposeContent(input)
	})
}

// FuzzParseTopicIDs fuzzes the UUID-parsing path with arbitrary string slices.
func FuzzParseTopicIDs(f *testing.F) {
	f.Add("")
	f.Add("550e8400-e29b-41d4-a716-446655440000")
	f.Add("not-a-uuid")
	f.Add("'; DROP TABLE topics; --")
	f.Add("\x00")
	f.Add(strings.Repeat("f", 36))
	f.Add(uuid.New().String())

	f.Fuzz(func(t *testing.T, raw string) {
		var rawSlice []string
		if raw != "" {
			rawSlice = []string{raw}
		}
		// Must not panic on any input.
		_, _ = parseTopicIDs(rawSlice)
	})
}
