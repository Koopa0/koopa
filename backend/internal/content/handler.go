package content

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/koopa0/blog-backend/internal/api"
)

// storeErrors maps store sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT"},
}

// Cache TTLs for pre-serialized feed responses and knowledge graph.
// These caches expire on TTL only — no active invalidation on content writes.
// This is intentional: content mutations are infrequent and eventual consistency is acceptable.
const (
	graphTTL   = 10 * time.Minute
	rssTTL     = 10 * time.Minute
	sitemapTTL = 30 * time.Minute
)

// Handler handles content HTTP requests.
type Handler struct {
	store   *Store
	siteURL string
	logger  *slog.Logger

	graphCache *ristretto.Cache[string, *KnowledgeGraph]
	graphSF    singleflight.Group
	feedCache  *ristretto.Cache[string, []byte]
}

// NewHandler returns a content Handler.
func NewHandler(
	store *Store,
	siteURL string,
	graphCache *ristretto.Cache[string, *KnowledgeGraph],
	feedCache *ristretto.Cache[string, []byte],
	logger *slog.Logger,
) *Handler {
	return &Handler{
		store:      store,
		siteURL:    siteURL,
		graphCache: graphCache,
		feedCache:  feedCache,
		logger:     logger,
	}
}

// List handles GET /api/contents.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := h.parseFilter(r)
	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// BySlug handles GET /api/contents/{slug}.
func (h *Handler) BySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	c, err := h.store.ContentBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// ByType handles GET /api/contents/by-type/{type}.
func (h *Handler) ByType(w http.ResponseWriter, r *http.Request) {
	t := Type(r.PathValue("type"))
	if !t.Valid() {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content type")
		return
	}
	f := h.parseFilter(r)
	f.Type = &t
	contents, total, err := h.store.Contents(r.Context(), f)
	if err != nil {
		h.logger.Error("listing contents by type", "type", t, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list contents")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, f.Page, f.PerPage))
}

// Search handles GET /api/search.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "query parameter q is required")
		return
	}
	page, perPage := api.ParsePagination(r)
	contents, total, err := h.store.Search(r.Context(), q, page, perPage)
	if err != nil {
		h.logger.Error("searching contents", "query", q, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to search")
		return
	}
	api.Encode(w, http.StatusOK, api.PagedResponse(contents, total, page, perPage))
}

// RSS handles GET /api/feed/rss.
func (h *Handler) RSS(w http.ResponseWriter, r *http.Request) {
	if data, ok := h.feedCache.Get("rss"); ok {
		w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
		_, _ = w.Write(data) // best-effort
		return
	}

	contents, err := h.store.PublishedForRSS(r.Context(), 20)
	if err != nil {
		h.logger.Error("generating rss", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	type rssItem struct {
		XMLName     xml.Name `xml:"item"`
		Title       string   `xml:"title"`
		Link        string   `xml:"link"`
		Description string   `xml:"description"`
		PubDate     string   `xml:"pubDate"`
		GUID        string   `xml:"guid"`
	}

	type rssChannel struct {
		XMLName       xml.Name  `xml:"channel"`
		Title         string    `xml:"title"`
		Link          string    `xml:"link"`
		Description   string    `xml:"description"`
		LastBuildDate string    `xml:"lastBuildDate"`
		Items         []rssItem `xml:"item"`
	}

	type rss struct {
		XMLName xml.Name   `xml:"rss"`
		Version string     `xml:"version,attr"`
		Channel rssChannel `xml:"channel"`
	}

	items := make([]rssItem, len(contents))
	for i := range contents {
		c := contents[i]
		pubDate := ""
		if c.PublishedAt != nil {
			pubDate = c.PublishedAt.Format(time.RFC1123Z)
		}
		items[i] = rssItem{
			Title:       c.Title,
			Link:        fmt.Sprintf("%s/%s/%s", h.siteURL, c.Type, c.Slug),
			Description: c.Excerpt,
			PubDate:     pubDate,
			GUID:        c.ID.String(),
		}
	}

	feed := rss{
		Version: "2.0",
		Channel: rssChannel{
			Title:         "koopa0.dev",
			Link:          h.siteURL,
			Description:   "Koopa's knowledge engine",
			LastBuildDate: time.Now().Format(time.RFC1123Z),
			Items:         items,
		},
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		h.logger.Error("encoding rss", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	data := buf.Bytes()
	if !h.feedCache.SetWithTTL("rss", data, int64(len(data)), rssTTL) {
		h.logger.Warn("rss cache set rejected", "size", len(data))
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	_, _ = w.Write(data) // best-effort
}

// Sitemap handles GET /api/feed/sitemap.
func (h *Handler) Sitemap(w http.ResponseWriter, r *http.Request) {
	if data, ok := h.feedCache.Get("sitemap"); ok {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		_, _ = w.Write(data) // best-effort
		return
	}

	contents, err := h.store.AllPublishedSlugs(r.Context())
	if err != nil {
		h.logger.Error("generating sitemap", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	type sitemapURL struct {
		XMLName xml.Name `xml:"url"`
		Loc     string   `xml:"loc"`
		LastMod string   `xml:"lastmod"`
	}

	type urlSet struct {
		XMLName xml.Name     `xml:"urlset"`
		XMLNS   string       `xml:"xmlns,attr"`
		URLs    []sitemapURL `xml:"url"`
	}

	urls := make([]sitemapURL, len(contents))
	for i := range contents {
		c := contents[i]
		urls[i] = sitemapURL{
			Loc:     fmt.Sprintf("%s/%s/%s", h.siteURL, c.Type, c.Slug),
			LastMod: c.UpdatedAt.Format("2006-01-02"),
		}
	}

	sitemap := urlSet{
		XMLNS: "http://www.sitemaps.org/schemas/sitemap/0.9",
		URLs:  urls,
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(sitemap); err != nil {
		h.logger.Error("encoding sitemap", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	data := buf.Bytes()
	if !h.feedCache.SetWithTTL("sitemap", data, int64(len(data)), sitemapTTL) {
		h.logger.Warn("sitemap cache set rejected", "size", len(data))
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_, _ = w.Write(data) // best-effort
}

// Create handles POST /api/admin/contents.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, err := api.Decode[CreateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if p.Slug == "" || p.Title == "" || p.Type == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug, title, and type are required")
		return
	}
	if p.Status == "" {
		p.Status = StatusDraft
	}
	if p.ReviewLevel == "" {
		p.ReviewLevel = ReviewStandard
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}

	c, err := h.store.CreateContent(r.Context(), &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: c})
}

// Update handles PUT /api/admin/contents/{id}.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	p, err := api.Decode[UpdateParams](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	c, err := h.store.UpdateContent(r.Context(), id, &p)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

// Delete handles DELETE /api/admin/contents/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	if err := h.store.DeleteContent(r.Context(), id); err != nil {
		h.logger.Error("deleting content", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete content")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Publish handles POST /api/admin/contents/{id}/publish.
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid content id")
		return
	}

	c, err := h.store.PublishContent(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: c})
}

const maxSlugLength = 200

// Related handles GET /api/contents/related/{slug}.
func (h *Handler) Related(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if len(slug) > maxSlugLength {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid slug")
		return
	}

	limit := 5
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 20 {
			limit = v
		}
	}

	id, embedding, err := h.store.ContentEmbeddingBySlug(r.Context(), slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}

	if embedding == nil {
		api.Encode(w, http.StatusOK, api.Response{Data: []RelatedContent{}})
		return
	}

	related, err := h.store.SimilarContents(r.Context(), id, *embedding, limit)
	if err != nil {
		h.logger.Error("querying similar contents", "slug", slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to get related contents")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: related})
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

func (h *Handler) parseFilter(r *http.Request) Filter {
	page, perPage := api.ParsePagination(r)
	f := Filter{Page: page, PerPage: perPage}

	if t := r.URL.Query().Get("type"); t != "" {
		ct := Type(t)
		if ct.Valid() {
			f.Type = &ct
		}
	}
	if tag := r.URL.Query().Get("tag"); tag != "" {
		f.Tag = &tag
	}
	return f
}
