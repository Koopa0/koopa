package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/content"
)

// LibraryPipelineResponse is the payload for GET /api/admin/library/pipeline.
type LibraryPipelineResponse struct {
	DraftsNeedingWork []ContentBrief `json:"drafts_needing_work"`
	InReview          []ContentBrief `json:"in_review"`
	ReadyToPublish    []ContentBrief `json:"ready_to_publish"`
	RecentlyPublished []ContentBrief `json:"recently_published"`
}

// ContentBrief is a lightweight content view for pipeline lists.
type ContentBrief struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	Type        string `json:"type"`
	ReviewLevel string `json:"review_level"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
}

// LibraryPipeline handles GET /api/admin/library/pipeline.
func (h *Handler) LibraryPipeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := LibraryPipelineResponse{
		DraftsNeedingWork: []ContentBrief{},
		InReview:          []ContentBrief{},
		ReadyToPublish:    []ContentBrief{},
		RecentlyPublished: []ContentBrief{},
	}

	contentToBrief := func(c content.Content) ContentBrief {
		b := ContentBrief{
			ID:          c.ID.String(),
			Title:       c.Title,
			Slug:        c.Slug,
			Type:        string(c.Type),
			ReviewLevel: string(c.ReviewLevel),
			UpdatedAt:   c.UpdatedAt.Format(time.RFC3339),
		}
		if c.PublishedAt != nil {
			b.PublishedAt = c.PublishedAt.Format(time.RFC3339)
		}
		return b
	}

	// Drafts needing work.
	if drafts, err := h.contents.ByStatus(ctx, "draft", 10); err == nil {
		for i := range drafts {
			resp.DraftsNeedingWork = append(resp.DraftsNeedingWork, contentToBrief(drafts[i]))
		}
	}

	// Recently published.
	if published, err := h.contents.ByStatus(ctx, "published", 5); err == nil {
		for i := range published {
			resp.RecentlyPublished = append(resp.RecentlyPublished, contentToBrief(published[i]))
		}
	}

	api.Encode(w, http.StatusOK, resp)
}
