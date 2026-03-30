package session

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// Handler serves session note REST endpoints.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a session note Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// List handles GET /api/admin/session-notes?date=YYYY-MM-DD&type=plan&days=7
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	now := time.Now().UTC()
	endDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if d := q.Get("date"); d != "" {
		parsed, err := time.Parse(time.DateOnly, d)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "INVALID_DATE", "date must be YYYY-MM-DD")
			return
		}
		endDate = parsed
	}

	days := 1
	if d := q.Get("days"); d != "" {
		v, err := strconv.Atoi(d)
		if err != nil || v < 1 {
			api.Error(w, http.StatusBadRequest, "INVALID_DAYS", "days must be a positive integer")
			return
		}
		if v > 30 {
			v = 30
		}
		days = v
	}

	startDate := endDate.AddDate(0, 0, -(days - 1))

	var noteType *string
	if t := q.Get("type"); t != "" {
		switch t {
		case "plan", "reflection", "context", "metrics", "insight":
			noteType = &t
		default:
			api.Error(w, http.StatusBadRequest, "INVALID_TYPE", "type must be plan, reflection, context, metrics, or insight")
			return
		}
	}

	notes, err := h.store.NotesByDate(r.Context(), startDate, endDate, noteType)
	if err != nil {
		h.logger.Error("listing session notes", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list session notes")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: notes})
}

// insightEntry is the JSON representation of an insight for HTTP responses.
type insightEntry struct {
	ID          int64    `json:"id"`
	CreatedAt   string   `json:"created_at"`
	Content     string   `json:"content"`
	Hypothesis  string   `json:"hypothesis,omitempty"`
	Status      string   `json:"status"`
	Evidence    []string `json:"evidence"`
	SourceDates []string `json:"source_dates"`
	Project     string   `json:"project,omitempty"`
	Tags        []string `json:"tags"`
	Conclusion  string   `json:"conclusion,omitempty"`
}

// Insights handles GET /api/admin/insights?status=unverified&project=slug&limit=10
func (h *Handler) Insights(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// Lazy auto-archive stale insights (>14 days)
	cutoff := time.Now().AddDate(0, 0, -14)
	if n, err := h.store.ArchiveStaleInsights(ctx, cutoff); err != nil {
		h.logger.Error("auto-archiving stale insights", "error", err)
	} else if n > 0 {
		h.logger.Info("auto-archived stale insights", "count", n)
	}

	status := q.Get("status")
	if status == "" {
		status = "unverified"
	}
	limit := 10
	if v := q.Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	var statusFilter *string
	if status != "all" {
		statusFilter = &status
	}
	var projectFilter *string
	if p := q.Get("project"); p != "" {
		projectFilter = &p
	}

	notes, err := h.store.InsightsByStatus(ctx, statusFilter, projectFilter, int32(limit))
	if err != nil {
		h.logger.Error("listing insights", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list insights")
		return
	}

	unverifiedStatus := "unverified"
	unverifiedCount, countErr := h.store.CountInsightsByStatus(ctx, &unverifiedStatus)
	if countErr != nil {
		h.logger.Error("counting unverified insights", "error", countErr)
	}

	insights := make([]insightEntry, 0, len(notes))
	for i := range notes {
		insights = append(insights, parseInsightNote(&notes[i]))
	}

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"insights":         insights,
		"total":            len(insights),
		"unverified_count": unverifiedCount,
	}})
}

// updateInsightRequest is the JSON body for PUT /api/admin/insights/{id}.
type updateInsightRequest struct {
	Status         string `json:"status,omitempty"`
	AppendEvidence string `json:"append_evidence,omitempty"`
	Conclusion     string `json:"conclusion,omitempty"`
}

// UpdateInsight handles PUT /api/admin/insights/{id} — updates insight status/evidence.
func (h *Handler) UpdateInsight(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_ID", "invalid insight id")
		return
	}

	req, err := api.Decode[updateInsightRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if code, msg := validateInsightRequest(&req); code != "" {
		api.Error(w, http.StatusBadRequest, code, msg)
		return
	}

	ctx := r.Context()

	note, err := h.store.NoteByID(ctx, id)
	if err != nil {
		h.logger.Error("querying insight", "id", id, "error", err)
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "insight not found")
		return
	}
	if note.NoteType != "insight" {
		api.Error(w, http.StatusBadRequest, "NOT_INSIGHT", "note is not an insight")
		return
	}

	meta, err := parseNoteMetadata(note.Metadata)
	if err != nil {
		h.logger.Error("parsing insight metadata", "id", id, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to parse insight metadata")
		return
	}

	applyInsightUpdates(meta, &req)

	updatedMetadata, marshalErr := json.Marshal(meta)
	if marshalErr != nil {
		h.logger.Error("marshaling updated metadata", "error", marshalErr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update insight")
		return
	}

	updated, updateErr := h.store.UpdateNoteMetadata(ctx, &UpdateMetadataParams{
		ID:       id,
		Metadata: updatedMetadata,
	})
	if updateErr != nil {
		h.logger.Error("updating insight", "id", id, "error", updateErr)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to update insight")
		return
	}

	currentStatus, _ := meta["status"].(string)
	conclusion, _ := meta["conclusion"].(string)

	h.logger.Info("insight updated via http", "id", id, "status", currentStatus)

	api.Encode(w, http.StatusOK, api.Response{Data: map[string]any{
		"id":             updated.ID,
		"status":         currentStatus,
		"evidence_count": countEvidence(updated.Metadata),
		"conclusion":     conclusion,
		"updated_at":     time.Now().Format(time.RFC3339),
	}})
}

// validateInsightRequest checks required fields and status enum.
// Returns empty code on success.
func validateInsightRequest(req *updateInsightRequest) (code, msg string) {
	if req.Status == "" && req.AppendEvidence == "" && req.Conclusion == "" {
		return "MISSING_FIELDS", "at least one of status, append_evidence, or conclusion is required"
	}
	if req.Status != "" {
		switch req.Status {
		case "unverified", "verified", "invalidated", "archived":
			// valid
		default:
			return "INVALID_STATUS", "status must be unverified, verified, invalidated, or archived"
		}
	}
	return "", ""
}

// parseNoteMetadata unmarshals raw JSON metadata into a map.
func parseNoteMetadata(raw json.RawMessage) (map[string]any, error) {
	meta := make(map[string]any)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, err
		}
	}
	return meta, nil
}

// applyInsightUpdates merges request fields into the metadata map.
func applyInsightUpdates(meta map[string]any, req *updateInsightRequest) {
	if req.Status != "" {
		meta["status"] = req.Status
	}
	if req.AppendEvidence != "" {
		var evidence []any
		if ev, ok := meta["evidence"].([]any); ok {
			evidence = ev
		}
		evidence = append(evidence, req.AppendEvidence)
		meta["evidence"] = evidence
	}
	if req.Conclusion != "" {
		meta["conclusion"] = req.Conclusion
	}
}

// countEvidence returns the number of evidence entries in raw metadata JSON.
func countEvidence(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return 0
	}
	if ev, ok := m["evidence"].([]any); ok {
		return len(ev)
	}
	return 0
}

// parseInsightNote extracts structured fields from an insight note's metadata.
func parseInsightNote(n *Note) insightEntry {
	entry := insightEntry{
		ID:        n.ID,
		CreatedAt: n.CreatedAt.Format(time.DateOnly),
		Content:   n.Content,
		Evidence:  []string{},
		Tags:      []string{},
	}

	if len(n.Metadata) == 0 {
		return entry
	}

	var meta struct {
		Hypothesis  string   `json:"hypothesis"`
		Status      string   `json:"status"`
		Evidence    []string `json:"evidence"`
		SourceDates []string `json:"source_dates"`
		Project     string   `json:"project"`
		Tags        []string `json:"tags"`
		Conclusion  string   `json:"conclusion"`
	}
	if err := json.Unmarshal(n.Metadata, &meta); err != nil {
		return entry
	}

	entry.Hypothesis = meta.Hypothesis
	entry.Status = meta.Status
	entry.Project = meta.Project
	entry.Conclusion = meta.Conclusion
	if meta.Evidence != nil {
		entry.Evidence = meta.Evidence
	}
	if meta.SourceDates != nil {
		entry.SourceDates = meta.SourceDates
	} else {
		entry.SourceDates = []string{}
	}
	if meta.Tags != nil {
		entry.Tags = meta.Tags
	}

	return entry
}
