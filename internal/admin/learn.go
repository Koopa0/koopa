package admin

import (
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/learning"
)

// SeveritySummary breaks down weakness observation severity counts.
type SeveritySummary struct {
	Critical int64 `json:"critical"`
	Moderate int64 `json:"moderate"`
	Minor    int64 `json:"minor"`
}

// WeaknessSpotlight is the admin-facing weakness row with severity aggregation.
// LastPracticed is the date of the most recent observation; DaysSincePractice
// is the staleness signal computed from it.
type WeaknessSpotlight struct {
	ConceptSlug       string          `json:"concept_slug"`
	ConceptName       string          `json:"concept_name"`
	Domain            string          `json:"domain"`
	Category          string          `json:"category"`
	FailCount30d      int64           `json:"fail_count_30d"`
	SeveritySummary   SeveritySummary `json:"severity_summary"`
	SeverityScore     int64           `json:"severity_score"`
	LastPracticed     string          `json:"last_practiced"`
	DaysSincePractice int             `json:"days_since_practice"`
}

// LearnDashboard handles GET /api/admin/learn/dashboard.
func (h *Handler) LearnDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	since30d := now.AddDate(0, 0, -30)

	type resp struct {
		DueReviewsCount int                          `json:"due_reviews_count"`
		DueReviewsToday int                          `json:"due_reviews_today"`
		RecentSessions  []learning.Session           `json:"recent_sessions"`
		WeaknessSpot    []WeaknessSpotlight          `json:"weakness_spotlight"`
		MasteryByDomain []learning.ConceptMasteryRow `json:"mastery_by_domain"`
		Streak          struct {
			CurrentDays int `json:"current_days"`
		} `json:"streak"`
	}

	out := resp{
		RecentSessions:  []learning.Session{},
		WeaknessSpot:    []WeaknessSpotlight{},
		MasteryByDomain: []learning.ConceptMasteryRow{},
	}

	if n, err := h.learn.DueReviewCount(ctx, now); err == nil {
		out.DueReviewsCount = n
	}
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, h.loc)
	if n, err := h.learn.DueReviewCount(ctx, endOfDay); err == nil {
		out.DueReviewsToday = n
	}

	if sessions, err := h.learn.RecentSessions(ctx, nil, since30d, 10); err == nil && sessions != nil {
		out.RecentSessions = sessions
	}

	if ws, err := h.learn.WeaknessAnalysis(ctx, nil, since30d); err == nil {
		out.WeaknessSpot = make([]WeaknessSpotlight, len(ws))
		for i := range ws {
			row := &ws[i]
			// severity_score: critical*5 + moderate*2 + minor*1 (weighted ranking).
			score := row.CriticalCount*5 + row.ModerateCount*2 + row.MinorCount
			daysSince := int(now.Sub(row.LastSeenAt).Hours() / 24)
			out.WeaknessSpot[i] = WeaknessSpotlight{
				ConceptSlug:  row.ConceptSlug,
				ConceptName:  row.ConceptName,
				Domain:       row.Domain,
				Category:     row.Category,
				FailCount30d: row.OccurrenceCount,
				SeveritySummary: SeveritySummary{
					Critical: row.CriticalCount,
					Moderate: row.ModerateCount,
					Minor:    row.MinorCount,
				},
				SeverityScore:     score,
				LastPracticed:     row.LastSeenAt.Format(time.DateOnly),
				DaysSincePractice: daysSince,
			}
		}
	}

	if ms, err := h.learn.ConceptMastery(ctx, nil, since30d); err == nil && ms != nil {
		out.MasteryByDomain = ms
	}

	if s, err := h.learn.Streak(ctx); err == nil {
		out.Streak.CurrentDays = s
	}

	api.Encode(w, http.StatusOK, out)
}

// ConceptDrilldown handles GET /api/admin/learn/concepts/{slug}.
func (h *Handler) ConceptDrilldown(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "leetcode"
	}

	ctx := r.Context()

	concept, err := h.learn.ConceptBySlug(ctx, domain, slug)
	if err != nil {
		h.logger.Error("concept drilldown", "slug", slug, "error", err)
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "concept not found")
		return
	}

	observations, _ := h.learn.ObservationsByConcept(ctx, concept.ID, 50)
	if observations == nil {
		observations = []learning.ConceptObservation{}
	}

	attempts, _ := h.learn.AttemptsByConcept(ctx, concept.ID, 20)
	if attempts == nil {
		attempts = []learning.ConceptAttempt{}
	}

	items, _ := h.learn.ItemsByConcept(ctx, concept.ID)
	if items == nil {
		items = []learning.ConceptItem{}
	}

	// Build observation trend (group by month).
	type trendPoint struct {
		Date             string `json:"date"`
		WeaknessCount    int    `json:"weakness_count"`
		ImprovementCount int    `json:"improvement_count"`
		MasteryCount     int    `json:"mastery_count"`
	}
	trendMap := map[string]*trendPoint{}
	for i := range observations {
		month := observations[i].CreatedAt.Format("2006-01")
		pt, ok := trendMap[month]
		if !ok {
			pt = &trendPoint{Date: month}
			trendMap[month] = pt
		}
		switch observations[i].SignalType {
		case "weakness":
			pt.WeaknessCount++
		case "improvement":
			pt.ImprovementCount++
		case "mastery":
			pt.MasteryCount++
		}
	}
	trend := make([]trendPoint, 0, len(trendMap))
	for _, pt := range trendMap {
		trend = append(trend, *pt)
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"concept":           concept,
		"observation_trend": trend,
		"recent_attempts":   attempts,
		"observations":      observations,
		"related_items":     items,
	})
}

// ReviewQueue handles GET /api/admin/learn/review-queue.
func (h *Handler) ReviewQueue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, h.loc)
	endOfWeek := endOfDay.AddDate(0, 0, 7)

	dueToday, _ := h.learn.RetrievalQueue(ctx, nil, endOfDay, 50)
	if dueToday == nil {
		dueToday = []learning.RetrievalItem{}
	}

	dueWeekCount := 0
	if weekItems, err := h.learn.RetrievalQueue(ctx, nil, endOfWeek, 200); err == nil {
		dueWeekCount = len(weekItems)
	}

	overdueCount := 0
	if overdueItems, err := h.learn.RetrievalQueue(ctx, nil, now, 200); err == nil {
		overdueCount = len(overdueItems)
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"due_today":     dueToday,
		"due_this_week": dueWeekCount,
		"overdue":       overdueCount,
	})
}
