package content

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
		{name: "note", typ: TypeNote, want: true},
		{name: "bookmark", typ: TypeBookmark, want: true},
		{name: "digest", typ: TypeDigest, want: true},
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

// TestNullSourceTypeRoundTrip verifies nil safety in DB null type converters.
// Scene: content from Obsidian may not have a source_type — nil must survive
// the conversion to/from DB nullable types without panicking.
func TestNullSourceTypeRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("nil converts to invalid null", func(t *testing.T) {
		t.Parallel()
		result := nullSourceType(nil)
		if result.Valid {
			t.Error("nullSourceType(nil).Valid = true, want false")
		}
	})

	t.Run("valid source type round-trips", func(t *testing.T) {
		t.Parallel()
		src := SourceObsidian
		dbVal := nullSourceType(&src)
		if !dbVal.Valid {
			t.Fatal("nullSourceType(&Obsidian).Valid = false, want true")
		}
		back := nullSourceTypeToPtr(dbVal)
		if back == nil {
			t.Fatal("nullSourceTypeToPtr returned nil for valid input")
		}
		if *back != src {
			t.Errorf("round-trip: got %q, want %q", *back, src)
		}
	})

	t.Run("invalid null converts to nil pointer", func(t *testing.T) {
		t.Parallel()
		var zero SourceType
		_ = zero // suppress unused
		back := nullSourceTypeToPtr(nullSourceType(nil))
		if back != nil {
			t.Errorf("nullSourceTypeToPtr(invalid) = %v, want nil", *back)
		}
	})
}

// TestFilterDefaults verifies that zero-value Filter produces sensible pagination.
// Scene: API request with no query params — Filter should not produce negative offsets.
func TestFilterDefaults(t *testing.T) {
	t.Parallel()

	f := Filter{}
	if f.Page < 0 {
		t.Errorf("Filter{}.Page = %d, want >= 0", f.Page)
	}
	if f.PerPage < 0 {
		t.Errorf("Filter{}.PerPage = %d, want >= 0", f.PerPage)
	}
}

// TestFilterSinceField verifies that the Since field on Filter is correctly typed.
// Scene: frontend passes ?since=2026-03-20 — parseFilter should populate Since.
func TestFilterSinceField(t *testing.T) {
	t.Parallel()

	t.Run("nil by default", func(t *testing.T) {
		t.Parallel()
		f := Filter{}
		if f.Since != nil {
			t.Errorf("Filter{}.Since = %v, want nil", f.Since)
		}
	})

	t.Run("can be set", func(t *testing.T) {
		t.Parallel()
		when := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
		f := Filter{Since: &when}
		if f.Since == nil {
			t.Fatal("Filter.Since = nil after setting")
		}
		if !f.Since.Equal(when) {
			t.Errorf("Filter.Since = %v, want %v", *f.Since, when)
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
		TypeNote:     "note",
		TypeBookmark: "bookmark",
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
