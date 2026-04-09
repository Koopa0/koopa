package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// StudioOverview handles GET /api/admin/studio/overview.
func (h *Handler) StudioOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type directiveSummary struct {
		ID              int64   `json:"id"`
		Content         string  `json:"content"`
		Source          string  `json:"source"`
		Target          string  `json:"target"`
		Priority        string  `json:"priority"`
		LifecycleStatus string  `json:"lifecycle_status"`
		AcknowledgedAt  *string `json:"acknowledged_at,omitempty"`
		IssuedDate      string  `json:"issued_date"`
		AgeDays         int     `json:"age_days"`
	}

	type reportSummary struct {
		ID           int64  `json:"id"`
		Source       string `json:"source"`
		Content      string `json:"content"`
		ReportedDate string `json:"reported_date"`
		InResponseTo *int64 `json:"in_response_to,omitempty"`
	}

	type resp struct {
		OpenDirectives []directiveSummary `json:"open_directives"`
		RecentReports  []reportSummary    `json:"recent_reports"`
		Stats          struct {
			UnackedCount    int `json:"unacked_count"`
			InProgressCount int `json:"in_progress_count"`
		} `json:"stats"`
	}

	out := resp{
		OpenDirectives: []directiveSummary{},
		RecentReports:  []reportSummary{},
	}

	// Open directives.
	dirs, dErr := h.directives.OpenDirectives(ctx)
	if dErr != nil {
		h.logger.Warn("studio: open directives", "error", dErr)
	}
	for i := range dirs {
		d := &dirs[i]
		status := "pending"
		if d.AcknowledgedAt != nil {
			status = "acknowledged"
		}
		ds := directiveSummary{
			ID:              d.ID,
			Content:         d.Content,
			Source:          d.Source,
			Target:          d.Target,
			Priority:        d.Priority,
			LifecycleStatus: status,
			IssuedDate:      d.IssuedDate.Format(time.DateOnly),
			AgeDays:         int(time.Since(d.IssuedDate).Hours() / 24),
		}
		if d.AcknowledgedAt != nil {
			s := d.AcknowledgedAt.Format(time.RFC3339)
			ds.AcknowledgedAt = &s
			out.Stats.InProgressCount++
		} else {
			out.Stats.UnackedCount++
		}
		out.OpenDirectives = append(out.OpenDirectives, ds)
	}

	// Recent reports (last 30 days).
	since := time.Now().AddDate(0, 0, -30)
	if reports, err := h.reports.RecentReports(ctx, since, 20); err == nil {
		for i := range reports {
			rpt := &reports[i]
			contentExcerpt := rpt.Content
			if len(contentExcerpt) > 200 {
				contentExcerpt = contentExcerpt[:200] + "..."
			}
			out.RecentReports = append(out.RecentReports, reportSummary{
				ID:           rpt.ID,
				Source:       rpt.Source,
				Content:      contentExcerpt,
				ReportedDate: rpt.ReportedDate.Format(time.DateOnly),
				InResponseTo: rpt.InResponseTo,
			})
		}
	}

	api.Encode(w, http.StatusOK, out)
}
