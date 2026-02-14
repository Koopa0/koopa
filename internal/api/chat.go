package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/tools"
)

// SSE timeout for streaming connections.
const sseTimeout = 5 * time.Minute

// titleMaxLength is the maximum rune length for a fallback session title.
const titleMaxLength = 50

// Tool display info for JSON SSE events.
type toolDisplayInfo struct {
	StartMsg    string
	CompleteMsg string
	ErrorMsg    string
}

var toolDisplay = map[string]toolDisplayInfo{
	"web_search":              {StartMsg: "搜尋網路中...", CompleteMsg: "搜尋完成", ErrorMsg: "搜尋服務暫時無法使用，請稍後再試"},
	"web_fetch":               {StartMsg: "讀取網頁中...", CompleteMsg: "已讀取內容", ErrorMsg: "無法讀取網頁內容"},
	"read_file":               {StartMsg: "讀取檔案中...", CompleteMsg: "已讀取檔案", ErrorMsg: "無法讀取檔案"},
	"write_file":              {StartMsg: "寫入檔案中...", CompleteMsg: "已寫入檔案", ErrorMsg: "寫入檔案失敗"},
	"list_files":              {StartMsg: "瀏覽目錄中...", CompleteMsg: "目錄瀏覽完成", ErrorMsg: "無法瀏覽目錄"},
	"delete_file":             {StartMsg: "刪除檔案中...", CompleteMsg: "已刪除檔案", ErrorMsg: "刪除檔案失敗"},
	"get_file_info":           {StartMsg: "取得檔案資訊中...", CompleteMsg: "已取得檔案資訊", ErrorMsg: "無法取得檔案資訊"},
	"execute_command":         {StartMsg: "執行命令中...", CompleteMsg: "命令執行完成", ErrorMsg: "命令執行失敗"},
	"current_time":            {StartMsg: "取得時間中...", CompleteMsg: "時間已取得", ErrorMsg: "無法取得時間"},
	"get_env":                 {StartMsg: "取得環境變數中...", CompleteMsg: "環境變數已取得", ErrorMsg: "無法取得環境變數"},
	"search_history":          {StartMsg: "搜尋對話記錄中...", CompleteMsg: "對話記錄搜尋完成", ErrorMsg: "無法搜尋對話記錄"},
	"search_documents":        {StartMsg: "搜尋知識庫中...", CompleteMsg: "知識庫搜尋完成", ErrorMsg: "無法搜尋知識庫"},
	"search_system_knowledge": {StartMsg: "搜尋系統知識中...", CompleteMsg: "系統知識搜尋完成", ErrorMsg: "無法搜尋系統知識"},
	"knowledge_store":         {StartMsg: "儲存知識中...", CompleteMsg: "知識已儲存", ErrorMsg: "儲存知識失敗"},
}

var defaultToolDisplay = toolDisplayInfo{
	StartMsg:    "執行工具中...",
	CompleteMsg: "工具執行完成",
	ErrorMsg:    "工具執行失敗",
}

func getToolDisplay(name string) toolDisplayInfo {
	if info, ok := toolDisplay[name]; ok {
		return info
	}
	return defaultToolDisplay
}

// chatHandler handles chat-related API requests.
type chatHandler struct {
	logger   *slog.Logger
	agent    *chat.Agent // Optional: nil disables AI title generation
	flow     *chat.Flow
	sessions *sessionManager
}

// send handles POST /api/v1/chat — accepts JSON, sends message to chat flow.
func (h *chatHandler) send(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content   string `json:"content"`
		SessionID string `json:"sessionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "invalid request body", h.logger)
		return
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		WriteError(w, http.StatusBadRequest, "content_required", "content is required", h.logger)
		return
	}

	if req.SessionID == "" {
		WriteError(w, http.StatusBadRequest, "session_required", "sessionId is required", h.logger)
		return
	}

	sessionID, err := uuid.Parse(req.SessionID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_session", "invalid session ID", h.logger)
		return
	}

	if !h.sessionAccessAllowed(r, sessionID) {
		WriteError(w, http.StatusForbidden, "forbidden", "session access denied", h.logger)
		return
	}

	msgID := uuid.New().String()

	params := url.Values{}
	params.Set("msgId", msgID)
	params.Set("session_id", sessionID.String())
	params.Set("query", content)

	WriteJSON(w, http.StatusOK, map[string]string{
		"msgId":     msgID,
		"sessionId": sessionID.String(),
		"streamUrl": "/api/v1/chat/stream?" + params.Encode(),
	}, h.logger)
}

// sessionAccessAllowed checks whether the request may access the session.
// Returns true when no session manager is configured (unit tests, CLI mode).
// When configured, verifies the session belongs to the authenticated user.
func (h *chatHandler) sessionAccessAllowed(r *http.Request, sessionID uuid.UUID) bool {
	if h.sessions == nil {
		return true // no session manager → allow (test/CLI mode)
	}
	if h.sessions.store == nil {
		return false // configured but no store → deny
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok || userID == "" {
		return false
	}

	sess, err := h.sessions.store.Session(r.Context(), sessionID)
	if err != nil {
		return false
	}

	return sess.OwnerID == userID
}

// stream handles GET /api/v1/chat/stream — SSE endpoint with JSON events.
func (h *chatHandler) stream(w http.ResponseWriter, r *http.Request) {
	msgID := r.URL.Query().Get("msgId")
	sessionID := r.URL.Query().Get("session_id")
	query := r.URL.Query().Get("query")

	if msgID == "" || sessionID == "" || query == "" {
		WriteError(w, http.StatusBadRequest, "missing_params", "msgId, session_id, and query required", h.logger)
		return
	}

	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_session", "invalid session ID", h.logger)
		return
	}

	if !h.sessionAccessAllowed(r, parsedID) {
		WriteError(w, http.StatusForbidden, "forbidden", "session access denied", h.logger)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	if _, ok := w.(http.Flusher); !ok {
		WriteError(w, http.StatusInternalServerError, "sse_unsupported", "streaming not supported", h.logger)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), sseTimeout)
	defer cancel()

	if h.flow == nil {
		_ = sseEvent(w, "error", map[string]string{"error": "chat flow not initialized"})
		return
	}
	h.streamWithFlow(ctx, w, msgID, sessionID, query)
}

// sseEvent writes a single SSE event.
func sseEvent(w http.ResponseWriter, event string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal SSE data: %w", err)
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonData)
	if err != nil {
		return fmt.Errorf("write SSE event: %w", err)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// streamWithFlow uses the real chat.Flow for AI responses.
func (h *chatHandler) streamWithFlow(ctx context.Context, w http.ResponseWriter, msgID, sessionID, query string) {
	input := chat.Input{
		Query:     query,
		SessionID: sessionID,
	}

	// Create JSON tool emitter and inject into context
	emitter := &jsonToolEmitter{w: w, msgID: msgID}
	ctx = tools.ContextWithEmitter(ctx, emitter)

	h.logger.Debug("starting stream", "sessionId", sessionID)

	var (
		finalOutput chat.Output
		streamErr   error
	)

	for streamValue, err := range h.flow.Stream(ctx, input) {
		select {
		case <-ctx.Done():
			h.logContextDone(ctx, msgID)
			return
		default:
		}

		if err != nil {
			streamErr = err
			break
		}

		if streamValue.Done {
			finalOutput = streamValue.Output
			break
		}

		if streamValue.Stream.Text != "" {
			if err := sseEvent(w, "chunk", map[string]string{"msgId": msgID, "text": streamValue.Stream.Text}); err != nil {
				h.logger.Error("writing chunk", "error", err)
				return
			}
		}
	}

	if streamErr != nil {
		code, message := classifyError(streamErr)
		h.logger.Error("executing flow", "error", streamErr, "sessionId", sessionID)
		_ = sseEvent(w, "error", map[string]string{"msgId": msgID, "code": code, "message": message}) // best-effort: client may have disconnected
		return
	}

	// Generate title before sending done event
	title := h.maybeGenerateTitle(ctx, sessionID, query)

	// Send done event
	doneData := map[string]string{
		"msgId":     msgID,
		"sessionId": sessionID,
		"response":  finalOutput.Response,
	}
	if title != "" {
		doneData["title"] = title
	}
	_ = sseEvent(w, "done", doneData) // best-effort: client may have disconnected
}

// classifyError returns error code and user message based on error type.
func classifyError(err error) (code, message string) {
	switch {
	case errors.Is(err, chat.ErrInvalidSession):
		return "invalid_session", "Invalid session. Please refresh the page."
	case errors.Is(err, chat.ErrExecutionFailed):
		return "execution_failed", err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "Request timed out. Please try again."
	default:
		return "flow_error", "Failed to generate response. Please try again."
	}
}

// maybeGenerateTitle generates a session title if one doesn't exist.
// Uses Agent.GenerateTitle for AI-powered titles, falls back to truncation.
// Returns the generated title or empty string.
func (h *chatHandler) maybeGenerateTitle(ctx context.Context, sessionID, userMessage string) string {
	if h.sessions == nil || h.sessions.store == nil {
		return ""
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return ""
	}

	sess, err := h.sessions.store.Session(ctx, sessionUUID)
	if err != nil {
		return ""
	}

	if sess.Title != "" {
		return ""
	}

	var title string
	if h.agent != nil {
		title = h.agent.GenerateTitle(ctx, userMessage)
	}
	if title == "" {
		title = truncateForTitle(userMessage)
	}

	if err := h.sessions.store.UpdateSessionTitle(ctx, sessionUUID, title); err != nil {
		h.logger.Error("updating session title", "error", err, "session_id", sessionID)
		return ""
	}

	h.logger.Info("auto-generated session title", "session_id", sessionID, "title", title)
	return title
}

// truncateForTitle truncates a message to create a fallback session title.
func truncateForTitle(message string) string {
	message = strings.TrimSpace(message)
	runes := []rune(message)
	if len(runes) <= titleMaxLength {
		return message
	}

	truncated := string(runes[:titleMaxLength])
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > titleMaxLength/2 {
		truncated = truncated[:lastSpace]
	}

	return strings.TrimSpace(truncated) + "..."
}

func (h *chatHandler) logContextDone(ctx context.Context, msgID string) {
	if ctx.Err() == context.DeadlineExceeded {
		h.logger.Warn("SSE connection timeout", "msgId", msgID, "timeout", sseTimeout)
	} else {
		h.logger.Info("client disconnected", "msgId", msgID)
	}
}

// jsonToolEmitter implements tools.Emitter for JSON SSE events.
type jsonToolEmitter struct {
	w     http.ResponseWriter
	msgID string
}

func (e *jsonToolEmitter) OnToolStart(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, "tool_start", map[string]string{ // best-effort
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.StartMsg,
	})
}

func (e *jsonToolEmitter) OnToolComplete(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, "tool_complete", map[string]string{ // best-effort
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.CompleteMsg,
	})
}

func (e *jsonToolEmitter) OnToolError(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, "tool_error", map[string]string{ // best-effort
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.ErrorMsg,
	})
}

// Compile-time interface verification.
var _ tools.Emitter = (*jsonToolEmitter)(nil)
