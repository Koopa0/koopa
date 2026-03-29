package content

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// =============================================================================
// Type.Valid — adversarial inputs
// =============================================================================

// TestTypeValid_Adversarial verifies that malicious / exotic type strings are rejected.
// These rows live in the same table as valid cases to make it obvious what
// the boundary between valid and invalid looks like.
func TestTypeValid_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  Type
		want bool
	}{
		// adversarial
		{name: "sql injection", typ: "'; DROP TABLE contents;--", want: false},
		{name: "xss payload", typ: `<script>alert(1)</script>`, want: false},
		{name: "null byte in type", typ: "article\x00", want: false},
		{name: "unicode look-alike", typ: "аrticle", want: false}, // Cyrillic 'а'
		{name: "whitespace prefix", typ: " article", want: false},
		{name: "whitespace suffix", typ: "article ", want: false},
		{name: "path traversal fragment", typ: "../../etc/passwd", want: false},
		{name: "oversized string (512 chars)", typ: Type(strings.Repeat("a", 512)), want: false},
		// boundary
		{name: "empty string", typ: "", want: false},
		{name: "space only", typ: " ", want: false},
		// all valid types to ensure nothing regresses
		{name: "article", typ: TypeArticle, want: true},
		{name: "essay", typ: TypeEssay, want: true},
		{name: "build-log", typ: TypeBuildLog, want: true},
		{name: "til", typ: TypeTIL, want: true},
		{name: "note", typ: TypeNote, want: true},
		{name: "bookmark", typ: TypeBookmark, want: true},
		{name: "digest", typ: TypeDigest, want: true},
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

// =============================================================================
// nullSourceType converters — adversarial / boundary
// =============================================================================

// TestNullSourceType_AllValues verifies every SourceType constant round-trips
// correctly through the DB nullable wrapper.
func TestNullSourceType_AllValues(t *testing.T) {
	t.Parallel()

	sources := []SourceType{
		SourceObsidian, SourceNotion, SourceAIGenerated, SourceExternal, SourceManual,
	}
	for _, src := range sources {
		src := src
		t.Run(string(src), func(t *testing.T) {
			t.Parallel()
			dbVal := nullSourceType(&src)
			if !dbVal.Valid {
				t.Fatalf("nullSourceType(%q).Valid = false, want true", src)
			}
			back := nullSourceTypeToPtr(dbVal)
			if back == nil {
				t.Fatalf("nullSourceTypeToPtr(valid) = nil for source %q", src)
			}
			if *back != src {
				t.Errorf("round-trip(%q): got %q, want %q", src, *back, src)
			}
		})
	}
}

// =============================================================================
// cosineSimilarity — pure math, adversarial + boundary
// =============================================================================

// TestCosineSimilarity verifies the similarity function across all edge cases
// that matter for the knowledge graph: identical, orthogonal, mismatched
// lengths, zero vectors, NaN-inducing inputs.
func TestCosineSimilarity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b []float32
		want float64
		// wantRange allows fuzzy "in range [lo, hi]" checks for floating point
		lo, hi   float64
		useRange bool
	}{
		{
			name: "identical unit vectors",
			a:    []float32{1, 0, 0},
			b:    []float32{1, 0, 0},
			want: 1.0,
		},
		{
			name: "orthogonal vectors",
			a:    []float32{1, 0},
			b:    []float32{0, 1},
			want: 0.0,
		},
		{
			name: "opposite vectors",
			a:    []float32{1, 0},
			b:    []float32{-1, 0},
			want: -1.0,
		},
		{
			name: "different lengths returns 0",
			a:    []float32{1, 0},
			b:    []float32{1, 0, 0},
			want: 0.0,
		},
		{
			name: "empty vectors return 0",
			a:    []float32{},
			b:    []float32{},
			want: 0.0,
		},
		{
			name: "nil vectors return 0",
			a:    nil,
			b:    nil,
			want: 0.0,
		},
		{
			name: "zero vector (a) returns 0",
			a:    []float32{0, 0, 0},
			b:    []float32{1, 2, 3},
			want: 0.0,
		},
		{
			name: "zero vector (b) returns 0",
			a:    []float32{1, 2, 3},
			b:    []float32{0, 0, 0},
			want: 0.0,
		},
		{
			name:     "scaled vectors have similarity 1",
			a:        []float32{1, 2, 3},
			b:        []float32{2, 4, 6},
			useRange: true,
			lo:       0.9999,
			hi:       1.0001,
		},
		{
			name:     "typical embedding-like vectors",
			a:        []float32{0.1, 0.8, 0.3, 0.5},
			b:        []float32{0.2, 0.7, 0.1, 0.6},
			useRange: true,
			lo:       0.9,
			hi:       1.0,
		},
		{
			name: "single element identical",
			a:    []float32{5},
			b:    []float32{5},
			want: 1.0,
		},
		{
			name: "large vectors same direction",
			a:    []float32{1e10, 1e10},
			b:    []float32{1e10, 1e10},
			want: 1.0,
		},
		{
			name:     "very small values near zero",
			a:        []float32{1e-30, 1e-30},
			b:        []float32{1e-30, 1e-30},
			useRange: true,
			lo:       0.999,
			hi:       1.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cosineSimilarity(tt.a, tt.b)
			if math.IsNaN(got) {
				t.Fatalf("cosineSimilarity() = NaN — must never produce NaN")
			}
			if math.IsInf(got, 0) {
				t.Fatalf("cosineSimilarity() = Inf — must never produce Inf")
			}
			if tt.useRange {
				if got < tt.lo || got > tt.hi {
					t.Errorf("cosineSimilarity() = %v, want in [%v, %v]", got, tt.lo, tt.hi)
				}
				return
			}
			// Use EquateApprox for floating-point equality.
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("cosineSimilarity(%v, %v) mismatch (-want +got):\n%s", tt.a, tt.b, diff)
			}
		})
	}
}

// TestCosineSimilarity_ResultInRange verifies the result is always in [-1, 1]
// for any random-looking combination of float32 values.
func TestCosineSimilarity_ResultInRange(t *testing.T) {
	t.Parallel()

	// A set of vectors that stress-tests boundary behavior.
	cases := [][]float32{
		{0},
		{math.MaxFloat32},
		{-math.MaxFloat32},
		{math.SmallestNonzeroFloat32},
		{1, -1, 1, -1},
		{math.MaxFloat32, math.MaxFloat32},
		{math.SmallestNonzeroFloat32, math.SmallestNonzeroFloat32},
	}

	for _, a := range cases {
		for _, b := range cases {
			got := cosineSimilarity(a, b)
			if math.IsNaN(got) {
				t.Errorf("cosineSimilarity(%v, %v) = NaN", a, b)
			}
			if got < -1.0001 || got > 1.0001 {
				t.Errorf("cosineSimilarity(%v, %v) = %v, want in [-1, 1]", a, b, got)
			}
		}
	}
}

// =============================================================================
// appendTopN — pure logic, adversarial + boundary
// =============================================================================

// TestAppendTopN verifies that appendTopN maintains sorted descending order
// and trims to n entries.
func TestAppendTopN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		start []simEdge
		add   simEdge
		n     int
		want  []simEdge
	}{
		{
			name:  "empty slice, n=3",
			start: nil,
			add:   simEdge{peer: 0, sim: 0.9},
			n:     3,
			want:  []simEdge{{peer: 0, sim: 0.9}},
		},
		{
			name:  "new edge displaces lowest when full",
			start: []simEdge{{peer: 0, sim: 0.9}, {peer: 1, sim: 0.8}, {peer: 2, sim: 0.7}},
			add:   simEdge{peer: 3, sim: 0.95},
			n:     3,
			want:  []simEdge{{peer: 3, sim: 0.95}, {peer: 0, sim: 0.9}, {peer: 1, sim: 0.8}},
		},
		{
			name:  "new edge below threshold does not displace",
			start: []simEdge{{peer: 0, sim: 0.9}, {peer: 1, sim: 0.8}, {peer: 2, sim: 0.7}},
			add:   simEdge{peer: 3, sim: 0.5},
			n:     3,
			want:  []simEdge{{peer: 0, sim: 0.9}, {peer: 1, sim: 0.8}, {peer: 2, sim: 0.7}},
		},
		{
			name:  "n=1 only keeps best",
			start: nil,
			add:   simEdge{peer: 5, sim: 0.6},
			n:     1,
			want:  []simEdge{{peer: 5, sim: 0.6}},
		},
		{
			name:  "ties preserved in insertion order",
			start: []simEdge{{peer: 0, sim: 0.9}},
			add:   simEdge{peer: 1, sim: 0.9},
			n:     3,
			want:  []simEdge{{peer: 0, sim: 0.9}, {peer: 1, sim: 0.9}},
		},
		{
			name:  "zero similarity is kept when not at capacity",
			start: nil,
			add:   simEdge{peer: 0, sim: 0.0},
			n:     3,
			want:  []simEdge{{peer: 0, sim: 0.0}},
		},
		{
			name:  "negative similarity is kept when not at capacity",
			start: nil,
			add:   simEdge{peer: 0, sim: -0.5},
			n:     3,
			want:  []simEdge{{peer: 0, sim: -0.5}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := appendTopN(tt.start, tt.add, tt.n)
			if len(got) > tt.n {
				t.Errorf("appendTopN() returned %d edges, want <= %d", len(got), tt.n)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(simEdge{})); diff != "" {
				t.Errorf("appendTopN() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// =============================================================================
// buildGraphFromTopics — pure logic
// =============================================================================

// TestBuildGraphFromTopics verifies node/link generation from content nodes.
func TestBuildGraphFromTopics(t *testing.T) {
	t.Parallel()

	t.Run("empty input produces empty output", func(t *testing.T) {
		t.Parallel()
		nodes, links := buildGraphFromTopics(nil)
		if len(nodes) != 0 {
			t.Errorf("buildGraphFromTopics(nil) nodes len = %d, want 0", len(nodes))
		}
		if len(links) != 0 {
			t.Errorf("buildGraphFromTopics(nil) links len = %d, want 0", len(links))
		}
	})

	t.Run("single node no topics", func(t *testing.T) {
		t.Parallel()
		input := []contentNode{
			{slug: "my-post", title: "My Post", typ: "article"},
		}
		nodes, links := buildGraphFromTopics(input)
		// Should have exactly 1 content node, no topic nodes, no links.
		if len(nodes) != 1 {
			t.Errorf("nodes len = %d, want 1", len(nodes))
		}
		if len(links) != 0 {
			t.Errorf("links len = %d, want 0", len(links))
		}
		if nodes[0].Type != "content" {
			t.Errorf("nodes[0].Type = %q, want %q", nodes[0].Type, "content")
		}
	})

	t.Run("topic node count matches shared topics", func(t *testing.T) {
		t.Parallel()
		input := []contentNode{
			{slug: "post-a", title: "Post A", typ: "article", topics: []TopicRef{{Slug: "go", Name: "Go"}}},
			{slug: "post-b", title: "Post B", typ: "article", topics: []TopicRef{{Slug: "go", Name: "Go"}}},
		}
		nodes, links := buildGraphFromTopics(input)

		// 2 content nodes + 1 topic node (go)
		if len(nodes) != 3 {
			t.Errorf("nodes len = %d, want 3", len(nodes))
		}
		// 2 content→topic links
		if len(links) != 2 {
			t.Errorf("links len = %d, want 2", len(links))
		}
	})

	t.Run("topic node has correct count", func(t *testing.T) {
		t.Parallel()
		input := []contentNode{
			{slug: "a", typ: "article", topics: []TopicRef{{Slug: "go", Name: "Go"}}},
			{slug: "b", typ: "article", topics: []TopicRef{{Slug: "go", Name: "Go"}}},
			{slug: "c", typ: "article", topics: []TopicRef{{Slug: "go", Name: "Go"}}},
		}
		nodes, _ := buildGraphFromTopics(input)

		var topicNode *GraphNode
		for i := range nodes {
			if nodes[i].Type == "topic" {
				topicNode = &nodes[i]
				break
			}
		}
		if topicNode == nil {
			t.Fatal("no topic node found")
		}
		if topicNode.Count != 3 {
			t.Errorf("topic node count = %d, want 3", topicNode.Count)
		}
	})

	t.Run("first topic is used as node Topic field", func(t *testing.T) {
		t.Parallel()
		input := []contentNode{
			{
				slug: "multi-topic",
				typ:  "article",
				topics: []TopicRef{
					{Slug: "primary", Name: "Primary"},
					{Slug: "secondary", Name: "Secondary"},
				},
			},
		}
		nodes, links := buildGraphFromTopics(input)

		// 1 content + 2 topic nodes
		if len(nodes) != 3 {
			t.Fatalf("nodes len = %d, want 3", len(nodes))
		}
		contentNode := nodes[0] // first node is always the content node
		if contentNode.Topic != "primary" {
			t.Errorf("content node Topic = %q, want %q", contentNode.Topic, "primary")
		}
		// 2 topic links
		if len(links) != 2 {
			t.Errorf("links len = %d, want 2", len(links))
		}
	})

	t.Run("adversarial: xss in slug and title", func(t *testing.T) {
		t.Parallel()
		input := []contentNode{
			{
				slug:  `<script>alert(1)</script>`,
				title: `"; DROP TABLE nodes;--`,
				typ:   "article",
			},
		}
		nodes, _ := buildGraphFromTopics(input)
		// The graph builder must not panic. Values pass through unescaped
		// (escaping is the responsibility of the rendering layer).
		if len(nodes) != 1 {
			t.Errorf("nodes len = %d, want 1", len(nodes))
		}
		if nodes[0].ID != input[0].slug {
			t.Errorf("node ID = %q, want %q", nodes[0].ID, input[0].slug)
		}
	})
}

// =============================================================================
// appendSimilarityEdges — deduplication logic
// =============================================================================

// TestAppendSimilarityEdges verifies edge deduplication: (A,B) and (B,A) must
// produce exactly one edge in the output.
func TestAppendSimilarityEdges(t *testing.T) {
	t.Parallel()

	t.Run("two similar nodes produce one edge", func(t *testing.T) {
		t.Parallel()
		e1 := []float32{1, 0, 0}
		e2 := []float32{0.99, 0.01, 0}
		nodes := []contentNode{
			{slug: "a", embedding: e1},
			{slug: "b", embedding: e2},
		}
		links := appendSimilarityEdges(nil, nodes)
		// similarity ~0.9999 > threshold 0.75, so one edge expected
		if len(links) != 1 {
			t.Errorf("appendSimilarityEdges() links len = %d, want 1", len(links))
		}
		if links[0].Type != "similar" {
			t.Errorf("link type = %q, want %q", links[0].Type, "similar")
		}
		if links[0].Similarity == nil {
			t.Fatal("link Similarity is nil, want non-nil")
		}
	})

	t.Run("low similarity produces no edge", func(t *testing.T) {
		t.Parallel()
		nodes := []contentNode{
			{slug: "a", embedding: []float32{1, 0, 0}},
			{slug: "b", embedding: []float32{0, 1, 0}}, // orthogonal → similarity 0
		}
		links := appendSimilarityEdges(nil, nodes)
		if len(links) != 0 {
			t.Errorf("appendSimilarityEdges() links len = %d, want 0", len(links))
		}
	})

	t.Run("empty nodes produces no edges", func(t *testing.T) {
		t.Parallel()
		links := appendSimilarityEdges(nil, nil)
		if len(links) != 0 {
			t.Errorf("appendSimilarityEdges(nil, nil) len = %d, want 0", len(links))
		}
	})

	t.Run("no duplicate edges for symmetric pairs", func(t *testing.T) {
		t.Parallel()
		// Three nearly-identical nodes → 3 edges (A-B, A-C, B-C), not 6.
		v := []float32{1, 0, 0}
		nodes := []contentNode{
			{slug: "a", embedding: v},
			{slug: "b", embedding: v},
			{slug: "c", embedding: v},
		}
		links := appendSimilarityEdges(nil, nodes)

		// Count unique pairs
		type pair struct{ a, b string }
		seen := make(map[pair]bool)
		for _, l := range links {
			p := pair{l.Source, l.Target}
			rev := pair{l.Target, l.Source}
			if seen[p] || seen[rev] {
				t.Errorf("duplicate edge (%q, %q)", l.Source, l.Target)
			}
			seen[p] = true
		}
	})
}

// =============================================================================
// nullContentType / nullContentStatus / nullReviewLevel — boundary
// =============================================================================

// TestNullConverters_Nil verifies all null converters produce invalid (null)
// DB values when given a nil pointer.
func TestNullConverters_Nil(t *testing.T) {
	t.Parallel()

	t.Run("nullContentType(nil)", func(t *testing.T) {
		t.Parallel()
		if nullContentType(nil).Valid {
			t.Error("nullContentType(nil).Valid = true, want false")
		}
	})
	t.Run("nullContentStatus(nil)", func(t *testing.T) {
		t.Parallel()
		if nullContentStatus(nil).Valid {
			t.Error("nullContentStatus(nil).Valid = true, want false")
		}
	})
	t.Run("nullReviewLevel(nil)", func(t *testing.T) {
		t.Parallel()
		if nullReviewLevel(nil).Valid {
			t.Error("nullReviewLevel(nil).Valid = true, want false")
		}
	})
	t.Run("nullVisibility(nil)", func(t *testing.T) {
		t.Parallel()
		if nullVisibility(nil) != nil {
			t.Error("nullVisibility(nil) = non-nil, want nil")
		}
	})
}

// =============================================================================
// Content JSON serialisation — contract
// =============================================================================

// TestContent_JSONContract verifies the exact JSON field names produced by
// json.Marshal for a Content value. This is the contract the frontend depends
// on — any field rename or omission breaks the API.
func TestContent_JSONContract(t *testing.T) {
	t.Parallel()

	src := SourceObsidian
	pub := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	c := Content{
		Slug:        "test-slug",
		Title:       "Test Title",
		Body:        "body text",
		Excerpt:     "excerpt",
		Type:        TypeArticle,
		Status:      StatusPublished,
		Tags:        []string{"go", "testing"},
		Topics:      []TopicRef{},
		SourceType:  &src,
		ReviewLevel: ReviewStandard,
		Visibility:  VisibilityPublic,
		ReadingTime: 5,
		PublishedAt: &pub,
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal(Content) error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshalling Content JSON: %v", err)
	}

	// These fields MUST be present and non-null in the serialised output.
	requiredFields := []string{
		"id", "slug", "title", "body", "excerpt",
		"type", "status", "tags", "topics",
		"review_level", "visibility", "reading_time",
		"created_at", "updated_at",
	}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Content JSON missing required field %q", field)
		}
	}

	// Tags must be [] not null when empty.
	c.Tags = []string{}
	emptyData, _ := json.Marshal(c)
	var emptyRaw map[string]json.RawMessage
	_ = json.Unmarshal(emptyData, &emptyRaw)
	if string(emptyRaw["tags"]) == "null" {
		t.Errorf("Content.Tags = [] should serialise as [], got null")
	}

	// Optional omitempty fields must not appear when nil.
	omitFields := []string{"source", "source_type", "series_id", "series_order",
		"project_id", "ai_metadata", "cover_image"}
	noOptionalData, _ := json.Marshal(Content{
		Tags:   []string{},
		Topics: []TopicRef{},
	})
	var noOptRaw map[string]json.RawMessage
	_ = json.Unmarshal(noOptionalData, &noOptRaw)
	for _, field := range omitFields {
		if _, ok := noOptRaw[field]; ok {
			t.Errorf("Content JSON has unexpected field %q when value is nil/zero", field)
		}
	}
}

// TestTopicRef_JSONContract verifies TopicRef field names.
func TestTopicRef_JSONContract(t *testing.T) {
	t.Parallel()

	tr := TopicRef{Slug: "golang", Name: "Go Language"}
	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("json.Marshal(TopicRef) error: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshalling TopicRef JSON: %v", err)
	}
	for _, field := range []string{"id", "slug", "name"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("TopicRef JSON missing field %q", field)
		}
	}
}

// TestKnowledgeGraph_JSONContract verifies KnowledgeGraph field names.
func TestKnowledgeGraph_JSONContract(t *testing.T) {
	t.Parallel()

	sim := 0.85
	g := KnowledgeGraph{
		Nodes: []GraphNode{{ID: "a", Label: "A", Type: "content"}},
		Links: []GraphLink{{Source: "a", Target: "b", Type: "similar", Similarity: &sim}},
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("json.Marshal(KnowledgeGraph) error: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshalling JSON: %v", err)
	}
	for _, field := range []string{"nodes", "links"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("KnowledgeGraph JSON missing field %q", field)
		}
	}
}

// TestKnowledgeGraph_NullArraysNeverSerialise verifies that empty KnowledgeGraph
// serialises [] for nodes and links, not null.
// Scene: frontend calls graph.nodes.map() — null panics JavaScript.
func TestKnowledgeGraph_NullArraysNeverSerialise(t *testing.T) {
	t.Parallel()

	g := KnowledgeGraph{
		Nodes: []GraphNode{},
		Links: []GraphLink{},
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	if string(raw["nodes"]) == "null" {
		t.Error("KnowledgeGraph.Nodes serialised as null, want []")
	}
	if string(raw["links"]) == "null" {
		t.Error("KnowledgeGraph.Links serialised as null, want []")
	}
}

// =============================================================================
// Benchmarks — hot-path functions
// =============================================================================

// BenchmarkCosineSimilarity measures the hot path inside knowledge graph build.
// Primary signal: allocs/op must be 0 (pure math, no heap allocation).
func BenchmarkCosineSimilarity(b *testing.B) {
	a := make([]float32, 1536) // typical OpenAI embedding dimension
	v := make([]float32, 1536)
	for i := range a {
		a[i] = float32(i) / 1536
		v[i] = float32(1536-i) / 1536
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = cosineSimilarity(a, v)
	}
}

// BenchmarkAppendTopN measures the insertion-sort-based top-N filter.
// n is small (maxSimilarPerNode=3), so this should be allocation-free.
func BenchmarkAppendTopN(b *testing.B) {
	edges := []simEdge{
		{peer: 0, sim: 0.9},
		{peer: 1, sim: 0.85},
		{peer: 2, sim: 0.8},
	}
	e := simEdge{peer: 3, sim: 0.95}
	b.ReportAllocs()
	for b.Loop() {
		_ = appendTopN(edges, e, 3)
	}
}

// BenchmarkBuildGraphFromTopics measures the topic graph assembly for a
// realistic number of content nodes (100 posts, 5 topics).
func BenchmarkBuildGraphFromTopics(b *testing.B) {
	topics := []TopicRef{
		{Slug: "go", Name: "Go"},
		{Slug: "databases", Name: "Databases"},
		{Slug: "architecture", Name: "Architecture"},
	}
	nodes := make([]contentNode, 100)
	for i := range nodes {
		nodes[i] = contentNode{
			slug:      "post-" + string(rune('a'+i%26)),
			title:     "Post Title",
			typ:       "article",
			topics:    topics[:1+(i%3)],
			embedding: []float32{float32(i) / 100, float32(100-i) / 100},
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = buildGraphFromTopics(nodes)
	}
}

// =============================================================================
// Fuzz tests
// =============================================================================

// FuzzTypeValid verifies that Type.Valid() never panics on arbitrary input.
func FuzzTypeValid(f *testing.F) {
	f.Add("article")
	f.Add("")
	f.Add("'; DROP TABLE contents;--")
	f.Add("<script>alert(1)</script>")
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("a", 10000))
	f.Fuzz(func(t *testing.T, input string) {
		_ = Type(input).Valid() // must not panic
	})
}

// FuzzCosineSimilarity verifies that cosineSimilarity never panics or returns
// NaN/Inf on arbitrary float32 slice inputs.
func FuzzCosineSimilarity(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x80, 0x3f}, []byte{0x00, 0x00, 0x80, 0x3f}) // [1.0] vs [1.0]
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, rawA, rawB []byte) {
		// Convert raw bytes to []float32 (4 bytes per element).
		toF32 := func(b []byte) []float32 {
			out := make([]float32, len(b)/4)
			for i := range out {
				bits := uint32(b[i*4]) | uint32(b[i*4+1])<<8 | uint32(b[i*4+2])<<16 | uint32(b[i*4+3])<<24
				out[i] = math.Float32frombits(bits)
			}
			return out
		}
		a := toF32(rawA)
		v := toF32(rawB)
		got := cosineSimilarity(a, v)
		if math.IsNaN(got) {
			t.Errorf("cosineSimilarity returned NaN for a=%v b=%v", a, v)
		}
		if math.IsInf(got, 0) {
			t.Errorf("cosineSimilarity returned Inf for a=%v b=%v", a, v)
		}
	})
}
