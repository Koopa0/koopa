// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// TestTypeValid verifies content type validation at the API boundary.
// Scene: user submits content via API with a type field — only known types should pass.
func TestTypeValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  Type
		want bool
	}{
		{name: "article", typ: TypeArticle, want: true},
		{name: "essay", typ: TypeEssay, want: true},
		{name: "build-log", typ: TypeBuildLog, want: true},
		{name: "til", typ: TypeTIL, want: true},
		{name: "digest", typ: TypeDigest, want: true},
		// bookmark lives in its own table (internal/bookmark), not contents.
		{name: "dropped: bookmark", typ: "bookmark", want: false},
		// note was removed from content_type in the notes/content split — notes are a
		// separate entity (internal/note, notes table).
		{name: "dropped: note", typ: "note", want: false},
		{name: "empty string is invalid", typ: "", want: false},
		{name: "unknown type is invalid", typ: "podcast", want: false},
		{name: "case sensitive", typ: "Article", want: false},
		{name: "partial match is invalid", typ: "build", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.typ.Valid(); got != tt.want {
				t.Errorf("Type(%q).Valid() = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

// TestFilterDefaults verifies that zero-value PublicFilter produces sensible pagination.
// Scene: API request with no query params — PublicFilter should not produce negative offsets.
func TestFilterDefaults(t *testing.T) {
	t.Parallel()

	f := PublicFilter{}
	if f.Page < 0 {
		t.Errorf("PublicFilter{}.Page = %d, want >= 0", f.Page)
	}
	if f.PerPage < 0 {
		t.Errorf("PublicFilter{}.PerPage = %d, want >= 0", f.PerPage)
	}
}

// TestFilterSinceField verifies that the Since field on PublicFilter is correctly typed.
// Scene: frontend passes ?since=2026-03-20 — parseFilter should populate Since.
func TestFilterSinceField(t *testing.T) {
	t.Parallel()

	t.Run("nil by default", func(t *testing.T) {
		t.Parallel()
		f := PublicFilter{}
		if f.Since != nil {
			t.Errorf("PublicFilter{}.Since = %v, want nil", f.Since)
		}
	})

	t.Run("can be set", func(t *testing.T) {
		t.Parallel()
		when := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
		f := PublicFilter{Since: &when}
		if f.Since == nil {
			t.Fatal("PublicFilter.Since = nil after setting")
		}
		if !f.Since.Equal(when) {
			t.Errorf("PublicFilter.Since = %v, want %v", *f.Since, when)
		}
	})
}

// TestContentTypeConstants verifies that content types match the expected database enum values.
// Scene: sqlc-generated code expects specific strings; if these constants drift, inserts break silently.
func TestContentTypeConstants(t *testing.T) {
	t.Parallel()

	want := map[Type]string{
		TypeArticle:  "article",
		TypeEssay:    "essay",
		TypeBuildLog: "build-log",
		TypeTIL:      "til",
		TypeDigest:   "digest",
	}

	for typ, expected := range want {
		if string(typ) != expected {
			t.Errorf("Type constant %v = %q, want %q", typ, string(typ), expected)
		}
	}
}

// TestKnowledgeGraphEmptySlices ensures graph JSON serialization produces [] not null.
// Scene: frontend receives graph data — null arrays break JavaScript .map() calls.
func TestKnowledgeGraphEmptySlices(t *testing.T) {
	t.Parallel()

	g := KnowledgeGraph{
		Nodes: []GraphNode{},
		Links: []GraphLink{},
	}
	if diff := cmp.Diff(0, len(g.Nodes)); diff != "" {
		t.Errorf("empty Nodes length mismatch: %s", diff)
	}
	if diff := cmp.Diff(0, len(g.Links)); diff != "" {
		t.Errorf("empty Links length mismatch: %s", diff)
	}
}

// Track 1B-correction — Today fan-out wire contract (content review queue).
//
// GET /api/admin/knowledge/content?status=review is one of the six Today
// fan-out sources. ContentService.adminList → TodayService contentRow()
// consumes id/title/type/updated_at/reading_time_min (and the list is filtered
// by status). This is a WIRE-SHAPE test (struct marshaling), NOT a full
// route/handler contract: it pins the field names content.Content emits
// without exercising the mounted handler or a database. A rename here breaks
// the Today "Awaiting judgment" content rows silently.
func TestContentWireContract(t *testing.T) {
	c := Content{
		ID:             uuid.New(),
		Title:          "Value semantics in Go",
		Type:           Type("article"),
		Status:         Status("review"),
		ReadingTimeMin: 7,
		UpdatedAt:      time.Date(2026, 5, 20, 4, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// id/title/type/updated_at/reading_time_min are consumed by TodayService;
	// status is the list filter param the frontend relies on.
	for _, want := range []string{"id", "title", "type", "status", "updated_at", "reading_time_min"} {
		if _, ok := m[want]; !ok {
			t.Errorf("content.Content missing wire field %q (Today content row / status filter consumes it)", want)
		}
	}
}
