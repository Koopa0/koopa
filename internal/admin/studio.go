package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/directive"
)

type directiveSummary struct {
	ID                 int64   `json:"id"`
	Content            string  `json:"content"`
	Source             string  `json:"source"`
	Target             string  `json:"target"`
	Priority           string  `json:"priority"`
	LifecycleStatus    string  `json:"lifecycle_status"`
	AcknowledgedAt     *string `json:"acknowledged_at,omitempty"`
	ResolvedAt         *string `json:"resolved_at,omitempty"`
	ResolutionReportID *int64  `json:"resolution_report_id,omitempty"`
	IssuedDate         string  `json:"issued_date"`
	AgeDays            int     `json:"age_days"`
	DaysToResolution   *int    `json:"days_to_resolution,omitempty"`
}

type reportSummary struct {
	ID           int64  `json:"id"`
	Source       string `json:"source"`
	Content      string `json:"content"`
	ReportedDate string `json:"reported_date"`
	InResponseTo *int64 `json:"in_response_to,omitempty"`
}

type studioParticipantSummary struct {
	Name                 string `json:"name"`
	Platform             string `json:"platform"`
	ActiveDirectives     int    `json:"active_directives"`
	RecentReports        int    `json:"recent_reports"`
	CanIssueDirectives   bool   `json:"can_issue_directives"`
	CanReceiveDirectives bool   `json:"can_receive_directives"`
	CanWriteReports      bool   `json:"can_write_reports"`
	TaskAssignable       bool   `json:"task_assignable"`
	HasSchedule          bool   `json:"has_schedule"`
}

// StudioOverview handles GET /api/admin/studio/overview.
//
// Query params:
//   - include_resolved=true — also return up to 20 most recently resolved directives
//     (Directive Board CEO history view).
func (h *Handler) StudioOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	includeResolved := r.URL.Query().Get("include_resolved") == "true"

	type resp struct {
		OpenDirectives     []directiveSummary         `json:"open_directives"`
		ResolvedDirectives []directiveSummary         `json:"resolved_directives,omitempty"`
		RecentReports      []reportSummary            `json:"recent_reports"`
		Participants       []studioParticipantSummary `json:"participants"`
		Stats              struct {
			UnackedCount    int `json:"unacked_count"`
			InProgressCount int `json:"in_progress_count"`
		} `json:"stats"`
	}

	out := resp{
		OpenDirectives: []directiveSummary{},
		RecentReports:  []reportSummary{},
		Participants:   []studioParticipantSummary{},
	}

	// Open directives.
	dirs, dErr := h.directives.OpenDirectives(ctx)
	if dErr != nil {
		h.logger.Warn("studio: open directives", "error", dErr)
	}
	for i := range dirs {
		d := &dirs[i]
		ds := summarizeDirective(d)
		if d.AcknowledgedAt != nil {
			out.Stats.InProgressCount++
		} else {
			out.Stats.UnackedCount++
		}
		out.OpenDirectives = append(out.OpenDirectives, ds)
	}

	// Resolved directives (optional history view).
	if includeResolved {
		out.ResolvedDirectives = []directiveSummary{}
		resolved, rErr := h.directives.ResolvedDirectivesRecent(ctx)
		if rErr != nil {
			h.logger.Warn("studio: resolved directives", "error", rErr)
		}
		for i := range resolved {
			out.ResolvedDirectives = append(out.ResolvedDirectives, summarizeDirective(&resolved[i]))
		}
	}

	// All reports, newest first.
	since := time.Now().AddDate(0, 0, -30)
	if reports, err := h.reports.RecentReports(ctx); err == nil {
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

	// Participants enriched with directive/report counts.
	if parts, err := h.directives.ParticipantsForStudio(ctx, since); err == nil {
		for i := range parts {
			p := &parts[i]
			out.Participants = append(out.Participants, studioParticipantSummary{
				Name:                 p.Name,
				Platform:             p.Platform,
				ActiveDirectives:     p.ActiveDirectives,
				RecentReports:        p.RecentReports,
				CanIssueDirectives:   p.CanIssueDirectives,
				CanReceiveDirectives: p.CanReceiveDirectives,
				CanWriteReports:      p.CanWriteReports,
				TaskAssignable:       p.TaskAssignable,
				HasSchedule:          p.HasSchedule,
			})
		}
	} else {
		h.logger.Warn("studio: participants", "error", err)
	}

	api.Encode(w, http.StatusOK, out)
}

// summarizeDirective converts a domain directive to its admin response shape.
// Computes lifecycle_status from acknowledged_at/resolved_at and derives
// days_to_resolution when both timestamps are present.
func summarizeDirective(d *directive.Directive) directiveSummary {
	status := "pending"
	switch {
	case d.ResolvedAt != nil:
		status = "resolved"
	case d.AcknowledgedAt != nil:
		status = "acknowledged"
	}

	ds := directiveSummary{
		ID:                 d.ID,
		Content:            d.Content,
		Source:             d.Source,
		Target:             d.Target,
		Priority:           d.Priority,
		LifecycleStatus:    status,
		ResolutionReportID: d.ResolutionReportID,
		IssuedDate:         d.IssuedDate.Format(time.DateOnly),
		AgeDays:            int(time.Since(d.IssuedDate).Hours() / 24),
	}
	if d.AcknowledgedAt != nil {
		s := d.AcknowledgedAt.Format(time.RFC3339)
		ds.AcknowledgedAt = &s
	}
	if d.ResolvedAt != nil {
		s := d.ResolvedAt.Format(time.RFC3339)
		ds.ResolvedAt = &s
		days := int(d.ResolvedAt.Sub(d.IssuedDate).Hours() / 24)
		ds.DaysToResolution = &days
	}
	return ds
}
