// Copyright 2026 Koopa. All rights reserved.

package content

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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
		// bookmark was never a content type; the bookmark feature was removed.
		{name: "dropped: bookmark", typ: "bookmark", want: false},
		// note was removed from content_type in the notes/content split — notes are a
		// separate entity (internal/note, notes table).
		{name: "dropped: note", typ: "note", want: false},
		{name: "empty string is invalid", typ: "", want: false},
		{name: "unknown type is invalid", typ: "podcast", want: false},
		{name: "case sensitive", typ: "Article", want: false},
		{name: "partial match is invalid", typ: "build", want: false},
		{name: "sql injection", typ: "'; DROP TABLE contents;--", want: false},
		{name: "xss payload", typ: `<script>alert(1)</script>`, want: false},
		{name: "unicode look-alike", typ: "аrticle", want: false}, // Cyrillic 'а'
		{name: "whitespace prefix", typ: " article", want: false},
		{name: "whitespace suffix", typ: "article ", want: false},
		{name: "oversized", typ: Type(strings.Repeat("a", 512)), want: false},
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
	for _, want := range []string{
		"id", "slug", "title", "body", "excerpt", "type", "status", "topics",
		"is_public", "reading_time_min", "created_at", "updated_at",
	} {
		if _, ok := m[want]; !ok {
			t.Errorf("content.Content missing wire field %q (Today content row / status filter consumes it)", want)
		}
	}
	for _, omitted := range []string{"series_id", "series_order", "project_id", "cover_image"} {
		if _, ok := m[omitted]; ok {
			t.Errorf("content.Content unexpectedly includes empty optional field %q", omitted)
		}
	}
}

func TestTopicRefWireContract(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(TopicRef{Slug: "golang", Name: "Go Language"})
	if err != nil {
		t.Fatalf("marshal TopicRef: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("unmarshal TopicRef: %v", err)
	}
	for _, field := range []string{"id", "slug", "name"} {
		if _, ok := fields[field]; !ok {
			t.Errorf("TopicRef missing wire field %q", field)
		}
	}
}

func TestNullConvertersNil(t *testing.T) {
	t.Parallel()

	if nullContentType(nil).Valid {
		t.Error("nullContentType(nil).Valid = true, want false")
	}
	if nullContentStatus(nil).Valid {
		t.Error("nullContentStatus(nil).Valid = true, want false")
	}
}

func FuzzTypeValid(f *testing.F) {
	f.Add("article")
	f.Add("")
	f.Add("'; DROP TABLE contents;--")
	f.Add("<script>alert(1)</script>")
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("a", 10_000))
	f.Fuzz(func(t *testing.T, input string) {
		_ = Type(input).Valid()
	})
}
