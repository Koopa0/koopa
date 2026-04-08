package admin

import (
	"net/http"
	"time"
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
	ID        string `json:"id"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	UpdatedAt string `json:"updated_at,omitempty"`
	WordCount int    `json:"word_count,omitempty"`
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

	// Drafts needing work.
	if drafts, err := h.contents.ByStatus(ctx, "draft", 10); err == nil {
		for i := range drafts {
			resp.DraftsNeedingWork = append(resp.DraftsNeedingWork, ContentBrief{
				ID:        drafts[i].ID.String(),
				Title:     drafts[i].Title,
				Type:      string(drafts[i].Type),
				UpdatedAt: drafts[i].UpdatedAt.Format(time.RFC3339),
			})
		}
	}

	// Recently published.
	if published, err := h.contents.ByStatus(ctx, "published", 5); err == nil {
		for i := range published {
			resp.RecentlyPublished = append(resp.RecentlyPublished, ContentBrief{
				ID:    published[i].ID.String(),
				Title: published[i].Title,
				Type:  string(published[i].Type),
			})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
