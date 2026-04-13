package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/consolidation"
	"github.com/Koopa0/koopa0.dev/internal/synthesis"
)

// ReflectHistoryWeeklyResponse is the retrospective listing payload
// for GET /api/admin/reflect/history/weekly. Each item is one frozen
// weekly snapshot the consolidation process has written. The list is
// ordered newest first; an empty list means no consolidation has run
// yet (not a cache miss, not an error).
type ReflectHistoryWeeklyResponse struct {
	Data []WeeklyHistoryItem `json:"data"`
}

// WeeklyHistoryItem is one historical weekly snapshot. body is the
// unmarshaled synthesis.WeeklyReviewBody. evidence_hash and
// computed_at expose the underlying provenance so a retrospective
// viewer can compare two snapshots of the same week and see when and
// why they diverged.
type WeeklyHistoryItem struct {
	WeekKey      string                     `json:"week_key"`
	ComputedAt   time.Time                  `json:"computed_at"`
	ComputedBy   string                     `json:"computed_by"`
	EvidenceHash string                     `json:"evidence_hash"`
	EvidenceSize int                        `json:"evidence_size"`
	Body         synthesis.WeeklyReviewBody `json:"body"`
}

// ReflectHistoryWeekly handles GET /api/admin/reflect/history/weekly.
//
// This is a PURE READ path over the synthesis historical substrate.
// It never triggers a live compute, never writes a row, and never
// falls through on a miss. If the table is empty the response is
// {"data": []} — that is a valid answer, not a cache miss.
//
// Query parameters:
//   - limit: 1..50, default 12 (roughly a quarter of weeks)
//   - week_key: optional, pin to a single ISO week key (e.g. "2026-W15")
func (h *Handler) ReflectHistoryWeekly(w http.ResponseWriter, r *http.Request) {
	limit := 12
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := parseBoundedInt(v, 1, 50); err == nil {
			limit = n
		}
	}

	var subjectKey *string
	if k := r.URL.Query().Get("week_key"); k != "" {
		subjectKey = &k
	}

	rows, err := h.synth.RecentByKind(
		r.Context(),
		synthesis.SubjectWeek,
		synthesis.KindWeeklyReview,
		subjectKey,
		limit,
	)
	if err != nil {
		h.logger.Error("reading weekly history", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to read weekly history")
		return
	}

	out := make([]WeeklyHistoryItem, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		var body synthesis.WeeklyReviewBody
		if err := json.Unmarshal(row.Body, &body); err != nil {
			h.logger.Error("unmarshaling synthesis body", "id", row.ID, "error", err)
			continue
		}
		weekKey := ""
		if row.SubjectKey != nil {
			weekKey = *row.SubjectKey
		}
		out = append(out, WeeklyHistoryItem{
			WeekKey:      weekKey,
			ComputedAt:   row.ComputedAt,
			ComputedBy:   row.ComputedBy,
			EvidenceHash: row.EvidenceHash,
			EvidenceSize: len(row.Evidence),
			Body:         body,
		})
	}

	api.Encode(w, http.StatusOK, ReflectHistoryWeeklyResponse{Data: out})
}

// ConsolidateWeeklyRequest is the POST payload for a manual weekly
// consolidation trigger. Week is optional — when empty, defaults to
// the most recently completed ISO week (i.e., the Monday before
// today's Monday). This matches the typical manual-replay flow:
// "snapshot last week now that it is done".
type ConsolidateWeeklyRequest struct {
	Week string `json:"week"`
}

// ConsolidateWeeklyResponse echoes the consolidation result to the
// caller so they can distinguish "new snapshot written" from "already
// up to date". Used by operators to verify a manual trigger.
type ConsolidateWeeklyResponse struct {
	WeekKey      string                     `json:"week_key"`
	Created      bool                       `json:"created"`
	EvidenceHash string                     `json:"evidence_hash"`
	EvidenceSize int                        `json:"evidence_size"`
	Body         synthesis.WeeklyReviewBody `json:"body"`
}

// ConsolidateWeekly handles POST /api/admin/consolidate/weekly.
//
// This is a MANUAL REPLAY trigger — it is the only admin endpoint
// that writes to the synthesis table, and it is named and documented
// so a reviewer cannot confuse it with a live read handler. The
// trigger is idempotent: invoking it twice for the same primary
// state is a no-op (ON CONFLICT DO NOTHING); invoking it after
// primary state has drifted produces a new synthesis row alongside
// the old one (historical accumulation).
func (h *Handler) ConsolidateWeekly(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[ConsolidateWeeklyRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	weekStart, err := resolveWeekStart(req.Week, h.loc)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	primary := consolidation.NewPrimaryReader(h.tasks, h.journal, h.learn)
	result, err := consolidation.RunWeekly(
		r.Context(),
		primary,
		h.synth,
		weekStart,
		consolidation.ComputedByWeeklyManual,
	)
	if err != nil {
		h.logger.Error("running weekly consolidation", "week_start", weekStart, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "consolidation failed")
		return
	}

	api.Encode(w, http.StatusOK, ConsolidateWeeklyResponse{
		WeekKey:      result.WeekKey,
		Created:      result.Created,
		EvidenceHash: result.EvidenceHash,
		EvidenceSize: result.EvidenceSize,
		Body:         result.Body,
	})
}

// resolveWeekStart parses the optional week key from a consolidation
// request. Empty input defaults to the most recently completed week.
// A non-empty input must be an ISO week key (YYYY-Www) or a
// YYYY-MM-DD date (interpreted as a day within the target week).
func resolveWeekStart(week string, loc *time.Location) (time.Time, error) {
	if loc == nil {
		loc = time.UTC
	}
	if week == "" {
		// Default: previous completed week. Today is always inside
		// the current (incomplete) week; stepping back 7 days gives
		// us a day in the previous week, from which MondayOf picks
		// the correct Monday.
		now := time.Now().In(loc)
		prevWeekDay := now.AddDate(0, 0, -7)
		return synthesis.MondayOf(prevWeekDay), nil
	}

	// Try ISO week key format first.
	if t, err := time.Parse("2006-W02", week); err == nil {
		return synthesis.MondayOf(t.In(loc)), nil
	}

	// Fall back to plain date.
	if t, err := time.Parse(time.DateOnly, week); err == nil {
		return synthesis.MondayOf(t.In(loc)), nil
	}

	return time.Time{}, errWeekFormat
}

var errWeekFormat = &weekFormatError{}

type weekFormatError struct{}

func (*weekFormatError) Error() string {
	return "week must be ISO week key (YYYY-Www) or date (YYYY-MM-DD)"
}

// parseBoundedInt parses a decimal integer and validates it against
// inclusive bounds. Used for the ?limit= parameter.
func parseBoundedInt(s string, lo, hi int) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errBadInt
		}
		n = n*10 + int(r-'0')
		if n > hi {
			return hi, nil
		}
	}
	if n < lo {
		return lo, nil
	}
	return n, nil
}

var errBadInt = &intFormatError{}

type intFormatError struct{}

func (*intFormatError) Error() string {
	return "not a valid integer"
}
