package admin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// InboxResponse is the payload for GET /api/admin/inbox.
type InboxResponse struct {
	Items []InboxItem `json:"items"`
	Stats InboxStats  `json:"stats"`
}

// InboxItem represents an unclarified inbox task.
type InboxItem struct {
	ID         string  `json:"id"`
	Text       string  `json:"text"`
	Source     string  `json:"source"`
	CapturedAt string  `json:"captured_at"`
	AgeHours   float64 `json:"age_hours"`
}

// InboxStats holds inbox summary counts.
type InboxStats struct {
	Total         int            `json:"total"`
	OldestAgeDays int            `json:"oldest_age_days"`
	BySource      map[string]int `json:"by_source"`
}

// Inbox handles GET /api/admin/inbox.
func (h *Handler) Inbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tasks, err := h.tasks.InboxTasks(ctx)
	if err != nil {
		h.logger.Error("inbox: listing", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	now := time.Now()
	items := make([]InboxItem, len(tasks))
	bySource := map[string]int{}
	var oldestAge float64

	for i := range tasks {
		t := &tasks[i]
		age := now.Sub(t.CreatedAt).Hours()
		items[i] = InboxItem{
			ID:         t.ID.String(),
			Text:       t.Title,
			Source:     t.CreatedBy,
			CapturedAt: t.CreatedAt.Format(time.RFC3339),
			AgeHours:   age,
		}
		bySource[t.CreatedBy]++
		if age > oldestAge {
			oldestAge = age
		}
	}

	api.Encode(w, http.StatusOK, InboxResponse{
		Items: items,
		Stats: InboxStats{
			Total:         len(items),
			OldestAgeDays: int(oldestAge / 24),
			BySource:      bySource,
		},
	})
}

// CaptureInboxRequest is the request body for POST /api/admin/inbox/capture.
type CaptureInboxRequest struct {
	Text string `json:"text"`
}

// InboxCapture handles POST /api/admin/inbox/capture.
func (h *Handler) InboxCapture(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[CaptureInboxRequest](w, r)
	if err != nil {
		return
	}
	if req.Text == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "text is required")
		return
	}

	t, err := h.tasks.Create(r.Context(), &task.CreateParams{
		Title:     req.Text,
		Assignee:  "human",
		CreatedBy: "human",
	})
	if err != nil {
		h.logger.Error("inbox capture", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	api.Encode(w, http.StatusCreated, map[string]any{
		"id":          t.ID.String(),
		"text":        t.Title,
		"captured_at": t.CreatedAt.Format(time.RFC3339),
	})
}

// ClarifyRequest is the polymorphic request for POST /api/admin/inbox/{id}/clarify.
type ClarifyRequest struct {
	Type                  string  `json:"type"` // task, journal, insight, discard
	AreaID                *string `json:"area_id,omitempty"`
	Priority              *string `json:"priority,omitempty"`
	Energy                *string `json:"energy,omitempty"`
	Due                   *string `json:"due,omitempty"`
	Kind                  *string `json:"kind,omitempty"` // for journal
	Body                  *string `json:"body,omitempty"` // for journal/insight
	Hypothesis            *string `json:"hypothesis,omitempty"`
	InvalidationCondition *string `json:"invalidation_condition,omitempty"`
}

// InboxClarify handles POST /api/admin/inbox/{id}/clarify.
func (h *Handler) InboxClarify(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	taskID, err := uuid.Parse(idStr)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid task id")
		return
	}

	req, err := api.Decode[ClarifyRequest](w, r)
	if err != nil {
		return
	}

	ctx := r.Context()

	switch req.Type {
	case "task":
		// Promote inbox → todo with clarification fields.
		var due *time.Time
		if req.Due != nil {
			d, pErr := time.Parse(time.DateOnly, *req.Due)
			if pErr != nil {
				api.Error(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("invalid due date: %s", *req.Due))
				return
			}
			due = &d
		}
		updated, cErr := h.tasks.Clarify(ctx, taskID, &task.ClarifyParams{
			Priority: req.Priority,
			Energy:   req.Energy,
			Due:      due,
		})
		if cErr != nil {
			h.logger.Error("inbox clarify task", "error", cErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
		api.Encode(w, http.StatusOK, map[string]any{
			"result":      "clarified",
			"entity_type": "task",
			"entity_id":   updated.ID.String(),
		})

	case "discard":
		if dErr := h.tasks.Delete(ctx, taskID); dErr != nil {
			h.logger.Error("inbox discard", "error", dErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
		api.Encode(w, http.StatusOK, map[string]any{
			"result":      "discarded",
			"entity_type": "task",
			"entity_id":   taskID.String(),
		})

	case "journal":
		if req.Body == nil || *req.Body == "" {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "body is required for journal clarification")
			return
		}
		kind := "reflection"
		if req.Kind != nil {
			kind = *req.Kind
		}
		entry, jErr := h.journal.Create(ctx, &journal.CreateParams{
			Kind:      journal.Kind(kind),
			Source:    "human",
			Content:   *req.Body,
			EntryDate: h.today(),
		})
		if jErr != nil {
			h.logger.Error("inbox clarify journal", "error", jErr)
			api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			return
		}
		// Delete the original inbox task.
		_ = h.tasks.Delete(ctx, taskID) // best-effort
		api.Encode(w, http.StatusOK, map[string]any{
			"result":      "clarified",
			"entity_type": "journal",
			"entity_id":   entry.ID,
		})

	default:
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("unsupported clarify type %q", req.Type))
	}
}
