// handler.go holds the admin HTTP handler for FSRS review recording.
// Other fsrs.Store responsibilities (card creation, drift marking)
// are system-internal — they fire from attempt recording and scheduler
// paths, not from REST.

package fsrs

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler handles review-recording HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns an fsrs Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (*Store, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("fsrs mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// ReviewRequest is the POST body for recording a review outcome.
// Rating vocabulary mirrors the FSRS rating scale — the handler maps it
// to the 1-4 integer rating the store takes.
type ReviewRequest struct {
	Rating    string     `json:"rating"`
	AttemptID *uuid.UUID `json:"attempt_id,omitempty"`
}

// Review handles POST /api/admin/learning/reviews/{card_id}. Records an
// FSRS rating for the card's underlying learning target and returns the
// next due date.
func (h *Handler) Review(w http.ResponseWriter, r *http.Request) {
	cardID, err := uuid.Parse(r.PathValue("card_id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid card id")
		return
	}
	req, err := api.Decode[ReviewRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	rating, err := ratingFromLabel(req.Rating)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	targetID, err := store.learningTargetByCardID(r.Context(), cardID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			api.Error(w, http.StatusNotFound, "NOT_FOUND", "review card not found")
			return
		}
		h.logger.Error("resolving review card", "card_id", cardID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to resolve review card")
		return
	}

	nextDue, err := store.ReviewByRating(r.Context(), targetID, rating, time.Now())
	if err != nil {
		h.logger.Error("recording review", "card_id", cardID, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to record review")
		return
	}

	type resp struct {
		CardID  uuid.UUID `json:"card_id"`
		NextDue time.Time `json:"next_due"`
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp{CardID: cardID, NextDue: nextDue}})
}

// ratingFromLabel maps the wire-level rating string to the 1-4 integer
// the FSRS scheduler expects. Closed set — unknown labels are a client
// error, not a server miscount.
func ratingFromLabel(label string) (int, error) {
	switch label {
	case "again":
		return 1, nil
	case "hard":
		return 2, nil
	case "good":
		return 3, nil
	case "easy":
		return 4, nil
	default:
		return 0, errors.New("rating must be one of: again, hard, good, easy")
	}
}

// learningTargetByCardID is a thin wrapper over the sqlc query so Handler
// does not reach into Store.q directly. Exposed unexported because the
// only consumer is this package's HTTP handler.
func (s *Store) learningTargetByCardID(ctx context.Context, cardID uuid.UUID) (uuid.UUID, error) {
	return s.q.LearningTargetByCardID(ctx, cardID)
}
