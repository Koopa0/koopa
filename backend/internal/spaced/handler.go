package spaced

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/koopa0/blog-backend/internal/api"
)

// maxDueResults is the upper bound for due interval listing.
const maxDueResults = 100

// Handler handles spaced repetition HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a spaced repetition Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// ListDue handles GET /api/admin/spaced/due — returns notes due for review.
func (h *Handler) ListDue(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= maxDueResults {
			limit = n
		}
	}

	intervals, err := h.store.DueIntervals(r.Context(), limit)
	if err != nil {
		h.logger.Error("listing due intervals", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list due intervals")
		return
	}

	count, err := h.store.DueCount(r.Context())
	if err != nil {
		h.logger.Error("counting due intervals", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to count due intervals")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{
		Data: map[string]any{
			"intervals": intervals,
			"total_due": count,
		},
	})
}

// reviewRequest is the JSON body for submitting a review.
type reviewRequest struct {
	NoteID  int64 `json:"note_id"`
	Quality int   `json:"quality"`
}

// SubmitReview handles POST /api/admin/spaced/review — processes a review.
func (h *Handler) SubmitReview(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[reviewRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.NoteID <= 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "note_id is required")
		return
	}
	if req.Quality < 0 || req.Quality > 5 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "quality must be 0-5")
		return
	}

	// Fetch current interval state.
	current, err := h.store.Interval(r.Context(), req.NoteID)
	if errors.Is(err, ErrNotFound) {
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "note not enrolled in spaced repetition")
		return
	}
	if err != nil {
		h.logger.Error("fetching interval for review", "note_id", req.NoteID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to fetch interval")
		return
	}

	// Compute next state via SM-2.
	out := SM2(SM2Input{
		Quality:        req.Quality,
		Repetitions:    current.Repetitions,
		EasinessFactor: current.EasinessFactor,
		IntervalDays:   current.IntervalDays,
	})

	now := time.Now()
	dueAt := now.Add(time.Duration(out.IntervalDays) * 24 * time.Hour)

	iv, err := h.store.UpsertInterval(r.Context(), UpsertParams{
		NoteID:         req.NoteID,
		EasinessFactor: out.EasinessFactor,
		IntervalDays:   out.IntervalDays,
		Repetitions:    out.Repetitions,
		LastQuality:    &req.Quality,
		DueAt:          dueAt,
		ReviewedAt:     &now,
	})
	if err != nil {
		h.logger.Error("upserting interval after review", "note_id", req.NoteID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to save review")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: iv})
}

// enrollRequest is the JSON body for enrolling a note.
type enrollRequest struct {
	NoteID int64 `json:"note_id"`
}

// Enroll handles POST /api/admin/spaced/enroll — enrolls a note for spaced repetition.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[enrollRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.NoteID <= 0 {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "note_id is required")
		return
	}

	// Atomic insert — ON CONFLICT DO NOTHING avoids check-then-act race.
	iv, err := h.store.InsertInterval(r.Context(), InsertParams{
		NoteID:         req.NoteID,
		EasinessFactor: DefaultEasinessFactor,
		IntervalDays:   0,
		Repetitions:    0,
		DueAt:          time.Now(),
	})
	if errors.Is(err, ErrConflict) {
		api.Error(w, http.StatusConflict, "CONFLICT", "note already enrolled")
		return
	}
	if err != nil {
		h.logger.Error("enrolling note", "note_id", req.NoteID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to enroll note")
		return
	}

	api.Encode(w, http.StatusCreated, api.Response{Data: iv})
}
