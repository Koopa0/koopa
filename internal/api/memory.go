package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/memory"
)

// memoryHandler holds dependencies for memory API endpoints.
type memoryHandler struct {
	store  *memory.Store
	logger *slog.Logger
}

// listMemories handles GET /api/v1/memories — returns paginated memories.
func (h *memoryHandler) listMemories(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	limit := min(parseIntParam(r, "limit", 50), 200)
	offset := parseIntParam(r, "offset", 0)
	if offset > 10000 {
		WriteError(w, http.StatusBadRequest, "invalid_offset", "offset must be 10000 or less", h.logger)
		return
	}

	memories, total, err := h.store.Memories(r.Context(), userID, limit, offset)
	if err != nil {
		h.logger.Error("listing memories", "error", err, "user_id", userID)
		WriteError(w, http.StatusInternalServerError, "list_failed", "failed to list memories", h.logger)
		return
	}

	items := make([]memoryItem, len(memories))
	for i, m := range memories {
		items[i] = toMemoryItem(m)
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	}, h.logger)
}

// getMemory handles GET /api/v1/memories/{id} — returns a single memory.
func (h *memoryHandler) getMemory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_id", "invalid memory ID", h.logger)
		return
	}

	m, err := h.store.Memory(r.Context(), id, userID)
	if err != nil {
		if h.mapMemoryError(w, err) {
			return
		}
		h.logger.Error("getting memory", "error", err, "id", id)
		WriteError(w, http.StatusInternalServerError, "get_failed", "failed to get memory", h.logger)
		return
	}

	WriteJSON(w, http.StatusOK, toMemoryItem(m), h.logger)
}

// updateMemoryRequest is the request body for PATCH /api/v1/memories/{id}.
type updateMemoryRequest struct {
	Active *bool `json:"active"`
}

// updateMemory handles PATCH /api/v1/memories/{id} — deactivates a memory.
func (h *memoryHandler) updateMemory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_id", "invalid memory ID", h.logger)
		return
	}

	// Limit request body to 1KB — the only valid payload is {"active": false}.
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	var req updateMemoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			WriteError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large", h.logger)
			return
		}
		WriteError(w, http.StatusBadRequest, "invalid_body", "invalid request body", h.logger)
		return
	}

	// Only deactivation is supported (active=false).
	if req.Active == nil || *req.Active {
		WriteError(w, http.StatusBadRequest, "invalid_operation", "only deactivation (active=false) is supported", h.logger)
		return
	}

	if err := h.store.Delete(r.Context(), id, userID); err != nil {
		if h.mapMemoryError(w, err) {
			return
		}
		h.logger.Error("updating memory", "error", err, "id", id)
		WriteError(w, http.StatusInternalServerError, "update_failed", "failed to update memory", h.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"}, h.logger)
}

// deleteMemory handles DELETE /api/v1/memories/{id} — soft-deletes a memory.
func (h *memoryHandler) deleteMemory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r, h.logger)
	if !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_id", "invalid memory ID", h.logger)
		return
	}

	if err := h.store.Delete(r.Context(), id, userID); err != nil {
		if h.mapMemoryError(w, err) {
			return
		}
		h.logger.Error("deleting memory", "error", err, "id", id)
		WriteError(w, http.StatusInternalServerError, "delete_failed", "failed to delete memory", h.logger)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, h.logger)
}

// mapMemoryError maps memory store errors to HTTP 404 to prevent IDOR enumeration.
// Returns true if the error was handled (response written), false otherwise.
// Both ErrNotFound and ErrForbidden map to 404 — a 403 would reveal that a memory
// with this ID exists but belongs to another user.
func (h *memoryHandler) mapMemoryError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, memory.ErrNotFound) || errors.Is(err, memory.ErrForbidden) {
		WriteError(w, http.StatusNotFound, "not_found", "memory not found", h.logger)
		return true
	}
	return false
}

// memoryItem is the JSON representation of a memory.
type memoryItem struct {
	ID         string  `json:"id"`
	Content    string  `json:"content"`
	Category   string  `json:"category"`
	Importance int     `json:"importance"`
	DecayScore float64 `json:"decayScore"`
	Active     bool    `json:"active"`
	CreatedAt  string  `json:"createdAt"`
	UpdatedAt  string  `json:"updatedAt"`
}

// toMemoryItem converts a memory.Memory to its JSON representation.
func toMemoryItem(m *memory.Memory) memoryItem {
	return memoryItem{
		ID:         m.ID.String(),
		Content:    m.Content,
		Category:   string(m.Category),
		Importance: m.Importance,
		DecayScore: m.DecayScore,
		Active:     m.Active,
		CreatedAt:  m.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  m.UpdatedAt.Format(time.RFC3339),
	}
}
