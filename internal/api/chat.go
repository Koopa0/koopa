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

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/agent/chat"
	"github.com/koopa0/koopa/internal/tools"
)

// SSE timeout for streaming connections.
const sseTimeout = 5 * time.Minute

// Title generation constants.
const (
	titleMaxLength         = 50
	titleGenerationTimeout = 5 * time.Second
	titleInputMaxRunes     = 500
)

const titlePrompt = `Generate a concise title (max 50 characters) for a chat session based on this first message.
The title should capture the main topic or intent.
Return ONLY the title text, no quotes, no explanations, no punctuation at the end.

Message: %s

Title:`

// Tool display info for JSON SSE events.
type toolDisplayInfo struct {
	StartMsg    string
	CompleteMsg string
	ErrorMsg    string
}

var toolDisplay = map[string]toolDisplayInfo{
	"web_search":       {StartMsg: "搜尋網路中...", CompleteMsg: "搜尋完成", ErrorMsg: "搜尋服務暫時無法使用，請稍後再試"},
	"web_fetch":        {StartMsg: "讀取網頁中...", CompleteMsg: "已讀取內容", ErrorMsg: "無法讀取網頁內容"},
	"read_file":        {StartMsg: "讀取檔案中...", CompleteMsg: "已讀取檔案", ErrorMsg: "無法讀取檔案"},
	"write_file":       {StartMsg: "寫入檔案中...", CompleteMsg: "已寫入檔案", ErrorMsg: "寫入檔案失敗"},
	"list_files":       {StartMsg: "瀏覽目錄中...", CompleteMsg: "目錄瀏覽完成", ErrorMsg: "無法瀏覽目錄"},
	"delete_file":      {StartMsg: "刪除檔案中...", CompleteMsg: "已刪除檔案", ErrorMsg: "刪除檔案失敗"},
	"get_file_info":    {StartMsg: "取得檔案資訊中...", CompleteMsg: "已取得檔案資訊", ErrorMsg: "無法取得檔案資訊"},
	"execute_command":  {StartMsg: "執行命令中...", CompleteMsg: "命令執行完成", ErrorMsg: "命令執行失敗"},
	"current_time":     {StartMsg: "取得時間中...", CompleteMsg: "時間已取得", ErrorMsg: "無法取得時間"},
	"get_env":          {StartMsg: "取得環境變數中...", CompleteMsg: "環境變數已取得", ErrorMsg: "無法取得環境變數"},
	"knowledge_search": {StartMsg: "搜尋知識庫中...", CompleteMsg: "知識庫搜尋完成", ErrorMsg: "無法搜尋知識庫"},
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
	logger    *slog.Logger
	genkit    *genkit.Genkit
	modelName string // Provider-qualified model name for title generation
	flow      *chat.Flow
	sessions  *sessionManager
}

// send handles POST /api/v1/chat — accepts JSON, sends message to chat flow.
//
//nolint:revive // unused-receiver: method bound to chatHandler for consistent route registration
func (h *chatHandler) send(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content   string `json:"content"`
		SessionID string `json:"sessionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		WriteError(w, http.StatusBadRequest, "content_required", "content is required")
		return
	}

	// Resolve session ID from request body or context
	var sessionID uuid.UUID
	if req.SessionID != "" {
		parsed, err := uuid.Parse(req.SessionID)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_session", "invalid session ID")
			return
		}
		sessionID = parsed
	} else {
		ctxID, ok := SessionIDFromContext(r.Context())
		if !ok {
			WriteError(w, http.StatusBadRequest, "session_required", "session ID required")
			return
		}
		sessionID = ctxID
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
	})
}

// stream handles GET /api/v1/chat/stream — SSE endpoint with JSON events.
func (h *chatHandler) stream(w http.ResponseWriter, r *http.Request) {
	msgID := r.URL.Query().Get("msgId")
	sessionID := r.URL.Query().Get("session_id")
	query := r.URL.Query().Get("query")

	if msgID == "" || sessionID == "" {
		WriteError(w, http.StatusBadRequest, "missing_params", "msgId and session_id required")
		return
	}
	if query == "" {
		query = "Hello"
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteError(w, http.StatusInternalServerError, "sse_unsupported", "streaming not supported")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), sseTimeout)
	defer cancel()

	if h.flow != nil {
		h.streamWithFlow(ctx, w, flusher, msgID, sessionID, query)
	} else {
		h.simulateStreaming(ctx, w, flusher, msgID, sessionID, query)
	}
}

// sseEvent writes a single SSE event.
func sseEvent(w http.ResponseWriter, f http.Flusher, event string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal SSE data: %w", err)
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonData)
	if err != nil {
		return fmt.Errorf("write SSE event: %w", err)
	}
	f.Flush()
	return nil
}

// streamWithFlow uses the real chat.Flow for AI responses.
func (h *chatHandler) streamWithFlow(ctx context.Context, w http.ResponseWriter, f http.Flusher, msgID, sessionID, query string) {
	input := chat.Input{
		Query:     query,
		SessionID: sessionID,
	}

	// Create JSON tool emitter and inject into context
	emitter := &jsonToolEmitter{w: w, f: f, msgID: msgID}
	ctx = tools.ContextWithEmitter(ctx, emitter)

	h.logger.Debug("starting stream", "sessionId", sessionID)

	var (
		finalOutput chat.Output
		streamErr   error
		buf         strings.Builder
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
			buf.WriteString(streamValue.Stream.Text)
			content := buf.String()
			buf.Reset()
			if err := sseEvent(w, f, "chunk", map[string]string{"msgId": msgID, "text": content}); err != nil {
				h.logger.Error("failed to write chunk", "error", err)
				return
			}
		}
	}

	if streamErr != nil {
		code, message := classifyError(streamErr)
		h.logger.Error("flow execution failed", "error", streamErr, "sessionId", sessionID)
		_ = sseEvent(w, f, "error", map[string]string{"msgId": msgID, "code": code, "message": message})
		return
	}

	// Flush remaining buffer
	if buf.Len() > 0 {
		_ = sseEvent(w, f, "chunk", map[string]string{"msgId": msgID, "text": buf.String()})
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
	_ = sseEvent(w, f, "done", doneData)
}

// simulateStreaming is a placeholder for testing without real Flow.
func (h *chatHandler) simulateStreaming(ctx context.Context, w http.ResponseWriter, f http.Flusher, msgID, sessionID, query string) {
	response := fmt.Sprintf("I received your message: %q. This is a simulated response.", query)
	words := strings.Fields(response)

	var full strings.Builder
	for i, word := range words {
		select {
		case <-ctx.Done():
			h.logContextDone(ctx, msgID)
			return
		default:
		}

		if i > 0 {
			full.WriteString(" ")
		}
		full.WriteString(word)

		if err := sseEvent(w, f, "chunk", map[string]string{"msgId": msgID, "text": full.String()}); err != nil {
			h.logger.Error("failed to send chunk", "error", err)
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	title := h.maybeGenerateTitle(ctx, sessionID, query)

	doneData := map[string]string{
		"msgId":     msgID,
		"sessionId": sessionID,
		"response":  full.String(),
	}
	if title != "" {
		doneData["title"] = title
	}
	_ = sseEvent(w, f, "done", doneData)
}

// classifyError returns error code and user message based on error type.
func classifyError(err error) (code, message string) {
	switch {
	case errors.Is(err, agent.ErrInvalidSession):
		return "invalid_session", "Invalid session. Please refresh the page."
	case errors.Is(err, agent.ErrExecutionFailed):
		return "execution_failed", err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "Request timed out. Please try again."
	default:
		return "flow_error", "Failed to generate response. Please try again."
	}
}

// maybeGenerateTitle generates a session title if one doesn't exist.
// Returns the generated title or empty string.
func (h *chatHandler) maybeGenerateTitle(ctx context.Context, sessionID, userMessage string) string {
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

	title := h.generateTitleWithAI(ctx, userMessage)
	if title == "" {
		title = truncateForTitle(userMessage)
	}

	if err := h.sessions.store.UpdateSessionTitle(ctx, sessionUUID, title); err != nil {
		h.logger.Error("failed to update session title", "error", err, "session_id", sessionID)
		return ""
	}

	h.logger.Info("auto-generated session title", "session_id", sessionID, "title", title)
	return title
}

// generateTitleWithAI uses Genkit to generate a session title.
func (h *chatHandler) generateTitleWithAI(ctx context.Context, userMessage string) string {
	if h.genkit == nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(ctx, titleGenerationTimeout)
	defer cancel()

	inputRunes := []rune(userMessage)
	if len(inputRunes) > titleInputMaxRunes {
		userMessage = string(inputRunes[:titleInputMaxRunes]) + "..."
	}

	response, err := genkit.Generate(ctx, h.genkit,
		ai.WithModelName(h.modelName),
		ai.WithPrompt(titlePrompt, userMessage),
	)
	if err != nil {
		h.logger.Debug("AI title generation failed", "error", err)
		return ""
	}

	title := strings.TrimSpace(response.Text())
	if title == "" {
		return ""
	}

	titleRunes := []rune(title)
	if len(titleRunes) > titleMaxLength {
		title = string(titleRunes[:titleMaxLength-3]) + "..."
	}

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

// jsonToolEmitter implements tools.ToolEventEmitter for JSON SSE events.
type jsonToolEmitter struct {
	w     http.ResponseWriter
	f     http.Flusher
	msgID string
}

func (e *jsonToolEmitter) OnToolStart(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, e.f, "tool_start", map[string]string{
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.StartMsg,
	})
}

func (e *jsonToolEmitter) OnToolComplete(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, e.f, "tool_complete", map[string]string{
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.CompleteMsg,
	})
}

func (e *jsonToolEmitter) OnToolError(name string) {
	display := getToolDisplay(name)
	_ = sseEvent(e.w, e.f, "tool_error", map[string]string{
		"msgId":   e.msgID,
		"tool":    name,
		"message": display.ErrorMsg,
	})
}

// Compile-time interface verification.
var _ tools.ToolEventEmitter = (*jsonToolEmitter)(nil)
