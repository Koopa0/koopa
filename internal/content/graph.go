// graph.go owns the knowledge-graph derivation — pgvector similarity
// queries + the topic/edge graph builders served to the admin UI. The
// core types and CRUD live in content.go; this file is where embedding
// math (cosine similarity, top-N selection) lives so content.go stays
// focused on row-shaped operations.

package content

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/db"
)

// SimilarContents returns published contents most similar to the given embedding.
func (s *Store) SimilarContents(ctx context.Context, excludeID uuid.UUID, embedding pgvector.Vector, limit int) ([]RelatedContent, error) {
	rows, err := s.q.SimilarContents(ctx, db.SimilarContentsParams{
		TargetEmbedding: embedding,
		ExcludeID:       excludeID,
		MaxResults:      int32(limit), // #nosec G115 -- limit is bounded by handler (max 20)
	})
	if err != nil {
		return nil, fmt.Errorf("querying similar contents: %w", err)
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	topicMap, err := s.topicsForContents(ctx, ids)
	if err != nil {
		return nil, err
	}

	results := make([]RelatedContent, len(rows))
	for i, r := range rows {
		results[i] = RelatedContent{
			Slug:       r.Slug,
			Title:      r.Title,
			Excerpt:    r.Excerpt,
			Type:       Type(r.Type),
			Similarity: r.Similarity,
			Topics:     topicMap[r.ID],
		}
	}
	return results, nil
}

// InternalSemanticSearch returns contents ranked by cosine similarity to
// the query embedding. Mirrors InternalSearch visibility — excludes only
// 'archived', includes drafts / private content. Contents without embeddings
// are skipped. Used by search_knowledge alongside InternalSearch (FTS) to
// feed hybrid retrieval.
func (s *Store) InternalSemanticSearch(ctx context.Context, queryEmbedding pgvector.Vector, limit int) ([]Content, error) {
	rows, err := s.q.InternalSemanticSearchContents(ctx, db.InternalSemanticSearchContentsParams{
		TargetEmbedding: queryEmbedding,
		MaxResults:      int32(limit), // #nosec G115 -- caller bounds limit via clamp
	})
	if err != nil {
		return nil, fmt.Errorf("semantic searching contents: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}
	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}
	return contents, nil
}

// ContentEmbeddingBySlug returns the ID and embedding for a content by slug.
func (s *Store) ContentEmbeddingBySlug(ctx context.Context, slug string) (uuid.UUID, *pgvector.Vector, error) {
	r, err := s.q.ContentEmbeddingBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil, ErrNotFound
		}
		return uuid.Nil, nil, fmt.Errorf("querying embedding for content %s: %w", slug, err)
	}
	return r.ID, r.Embedding, nil
}

// PublishedWithEmbeddings returns all published contents that have embeddings.
func (s *Store) PublishedWithEmbeddings(ctx context.Context) ([]EmbeddingContent, error) {
	rows, err := s.q.PublishedWithEmbeddings(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing published contents with embeddings: %w", err)
	}
	results := make([]EmbeddingContent, len(rows))
	for i, r := range rows {
		results[i] = EmbeddingContent{
			ID:    r.ID,
			Slug:  r.Slug,
			Title: r.Title,
			Type:  Type(r.Type),
		}
		if r.Embedding != nil {
			results[i].Embedding = r.Embedding.Slice()
		}
	}
	return results, nil
}

// KnowledgeGraph handles GET /api/knowledge-graph.
func (h *Handler) KnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	if graph, ok := h.graphCache.Get("graph"); ok {
		api.Encode(w, http.StatusOK, api.Response{Data: graph})
		return
	}

	// singleflight prevents thundering herd — only one goroutine builds the graph.
	// Use independent context so no single caller's timeout aborts the shared build.
	v, err, _ := h.graphSF.Do("graph", func() (any, error) {
		buildCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		graph, buildErr := h.buildKnowledgeGraph(buildCtx)
		if buildErr != nil {
			return nil, buildErr
		}
		if !h.graphCache.SetWithTTL("graph", graph, 1, graphTTL) {
			h.logger.Warn("graph cache set rejected")
		}
		h.graphCache.Wait()
		return graph, nil
	})
	if err != nil {
		h.logger.Error("building knowledge graph", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to build knowledge graph")
		return
	}

	graph, ok := v.(*KnowledgeGraph)
	if !ok {
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "unexpected graph type")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: graph})
}

const (
	// similarityThreshold is the minimum cosine similarity (0-1 scale) to create a "similar" edge.
	// 0.75 is conservative — only highly related content gets linked.
	similarityThreshold = 0.75
	// maxGraphNodes caps content nodes to bound the O(n²) pairwise computation.
	maxGraphNodes = 500
	// maxSimilarPerNode limits similarity edges per node to keep the graph readable.
	maxSimilarPerNode = 3
)

// contentNode holds the data needed to build graph nodes and edges.
type contentNode struct {
	slug      string
	title     string
	typ       string
	embedding []float32
	topics    []TopicRef
}

func (h *Handler) buildKnowledgeGraph(ctx context.Context) (*KnowledgeGraph, error) {
	rows, err := h.store.PublishedWithEmbeddings(ctx)
	if err != nil {
		return nil, err
	}

	// Cap the number of nodes to avoid excessive computation.
	if len(rows) > maxGraphNodes {
		rows = rows[:maxGraphNodes]
	}

	nodes, err := h.buildContentNodes(ctx, rows)
	if err != nil {
		return nil, err
	}

	graphNodes, graphLinks := buildGraphFromTopics(nodes)
	graphLinks = appendSimilarityEdges(graphLinks, nodes)

	return &KnowledgeGraph{Nodes: graphNodes, Links: graphLinks}, nil
}

// buildContentNodes fetches topics and assembles contentNode entries from published rows.
func (h *Handler) buildContentNodes(ctx context.Context, rows []EmbeddingContent) ([]contentNode, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	topicMap, err := h.store.topicsForContents(ctx, ids)
	if err != nil {
		return nil, err
	}

	nodes := make([]contentNode, 0, len(rows))
	for _, r := range rows {
		if len(r.Embedding) == 0 {
			continue
		}
		nodes = append(nodes, contentNode{
			slug:      r.Slug,
			title:     r.Title,
			typ:       string(r.Type),
			embedding: r.Embedding,
			topics:    topicMap[r.ID],
		})
	}
	return nodes, nil
}

// buildGraphFromTopics creates content graph nodes, topic graph nodes, and topic links.
func buildGraphFromTopics(nodes []contentNode) ([]GraphNode, []GraphLink) {
	topicCounts := make(map[string]int)
	topicNames := make(map[string]string)
	graphNodes := make([]GraphNode, 0, len(nodes)+len(topicCounts))
	var graphLinks []GraphLink

	for _, n := range nodes {
		firstTopic := ""
		if len(n.topics) > 0 {
			firstTopic = n.topics[0].Slug
		}
		graphNodes = append(graphNodes, GraphNode{
			ID:          n.slug,
			Label:       n.title,
			Type:        "content",
			ContentType: n.typ,
			Topic:       firstTopic,
		})
		for _, t := range n.topics {
			topicID := "topic-" + t.Slug
			topicCounts[topicID]++
			topicNames[topicID] = t.Name
			graphLinks = append(graphLinks, GraphLink{
				Source: n.slug,
				Target: topicID,
				Type:   "topic",
			})
		}
	}

	for id, count := range topicCounts {
		graphNodes = append(graphNodes, GraphNode{
			ID:    id,
			Label: topicNames[id],
			Type:  "topic",
			Count: count,
		})
	}

	return graphNodes, graphLinks
}

// appendSimilarityEdges computes pairwise cosine similarity and appends deduplicated edges.
// O(n²) in node count — bounded by maxGraphNodes (500) to ~125K comparisons.
// Cached via singleflight + Ristretto so this runs at most once per graphTTL window.
func appendSimilarityEdges(graphLinks []GraphLink, nodes []contentNode) []GraphLink {
	topEdges := make([][]simEdge, len(nodes))

	for i := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			sim := cosineSimilarity(nodes[i].embedding, nodes[j].embedding)
			if sim < similarityThreshold {
				continue
			}
			topEdges[i] = appendTopN(topEdges[i], simEdge{peer: j, sim: sim}, maxSimilarPerNode)
			topEdges[j] = appendTopN(topEdges[j], simEdge{peer: i, sim: sim}, maxSimilarPerNode)
		}
	}

	type edgeKey struct{ a, b int }
	seen := make(map[edgeKey]bool)
	for i, edges := range topEdges {
		for _, e := range edges {
			key := edgeKey{min(i, e.peer), max(i, e.peer)}
			if seen[key] {
				continue
			}
			seen[key] = true
			sim := e.sim
			graphLinks = append(graphLinks, GraphLink{
				Source:     nodes[i].slug,
				Target:     nodes[e.peer].slug,
				Type:       "similar",
				Similarity: &sim,
			})
		}
	}

	return graphLinks
}

type simEdge struct {
	peer int
	sim  float64
}

// appendTopN keeps the top-n highest similarity edges in a sorted slice.
func appendTopN(edges []simEdge, e simEdge, n int) []simEdge {
	edges = append(edges, e)
	// Sort descending by similarity using insertion sort (n is small).
	for i := len(edges) - 1; i > 0 && edges[i].sim > edges[i-1].sim; i-- {
		edges[i], edges[i-1] = edges[i-1], edges[i]
	}
	if len(edges) > n {
		edges = edges[:n]
	}
	return edges
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
