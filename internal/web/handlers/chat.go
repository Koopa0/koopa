// Package handlers provides HTTP handlers for the GenUI web interface.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/koopa0/koopa-cli/internal/web/sse"
)

// SSEWriter defines the interface for SSE streaming operations.
// This interface enables dependency injection for testing.
type SSEWriter interface {
	WriteChunkRaw(msgID, htmlContent string) error
	WriteDone(ctx context.Context, msgID string, comp templ.Component) error
	WriteError(msgID, code, message string) error
	WriteArtifact(ctx context.Context, comp templ.Component) error
	WriteCanvasShow() error
	WriteSidebarRefresh(sessionID, title string) error // For title auto-generation
}

// SSETimeout is the maximum duration for an SSE streaming connection.
// This prevents zombie goroutines from accumulating if clients disconnect
// without properly closing the connection.
const SSETimeout = 5 * time.Minute

// ChatConfig contains configuration for the Chat handler.
type ChatConfig struct {
	Logger      *slog.Logger
	Genkit      *genkit.Genkit                                 // Optional: nil disables AI title generation
	Flow        *chat.Flow                                     // Optional: nil enables simulation mode
	Sessions    *Sessions                                      // Session management
	SSEWriterFn func(w http.ResponseWriter) (SSEWriter, error) // Optional: nil uses default sse.NewWriter
}

// Chat handles chat-related HTTP requests.
// If flow is nil, the handler operates in simulation mode (returns canned responses).
// This allows development and testing without full Genkit initialization.
type Chat struct {
	logger      *slog.Logger
	genkit      *genkit.Genkit // Optional: nil disables AI title generation
	flow        *chat.Flow     // Optional: nil enables simulation mode
	sessions    *Sessions
	sseWriterFn func(w http.ResponseWriter) (SSEWriter, error)
}

// defaultSSEWriterFn wraps sse.NewWriter to return SSEWriter interface.
func defaultSSEWriterFn(w http.ResponseWriter) (SSEWriter, error) {
	return sse.NewWriter(w)
}

// NewChat creates a new Chat handler.
// logger is required (panics if nil).
// flow is optional - if nil, simulation mode is used.
// genkit is optional - if nil, AI title generation falls back to truncation.
func NewChat(cfg ChatConfig) *Chat {
	if cfg.Logger == nil {
		panic("NewChat: logger is required")
	}
	sseWriterFn := cfg.SSEWriterFn
	if sseWriterFn == nil {
		sseWriterFn = defaultSSEWriterFn
	}
	return &Chat{
		logger:      cfg.Logger,
		genkit:      cfg.Genkit,
		flow:        cfg.Flow,
		sessions:    cfg.Sessions,
		sseWriterFn: sseWriterFn,
	}
}

// =============================================================================
// Stream State and Helper Functions
// =============================================================================

// streamState encapsulates streaming state for a single response.
// Per rob-pike: State belongs in a struct, not passed as *bool.
type streamState struct {
	msgID       string
	sessionID   string
	buffer      strings.Builder
	canvasShown bool
}

// =============================================================================
// Session Title Auto-Generation
// =============================================================================

// TitleMaxLength is the maximum length for auto-generated session titles.
const TitleMaxLength = 50

// truncateForTitle truncates a message to create a session title.
// Fallback when AI title generation is unavailable.
// Rules:
// - Max 50 characters (runes, not bytes - supports UTF-8)
// - Truncates at word boundary if possible
// - Adds "..." if truncated
func truncateForTitle(message string) string {
	message = strings.TrimSpace(message)
	runes := []rune(message)
	if len(runes) <= TitleMaxLength {
		return message
	}

	// Try to truncate at word boundary
	truncated := string(runes[:TitleMaxLength])
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > TitleMaxLength/2 {
		truncated = truncated[:lastSpace]
	}

	return strings.TrimSpace(truncated) + "..."
}

// TitleGenerationTimeout is the maximum duration for AI title generation.
// Keep it short to avoid blocking the SSE stream too long.
const TitleGenerationTimeout = 5 * time.Second

// TitleGenerationModel is the model used for title generation.
// Using a fast model to minimize latency.
const TitleGenerationModel = "googleai/gemini-2.5-flash"

// TitleInputMaxRunes limits the user message length sent to the AI model
// for title generation, reducing latency and cost.
const TitleInputMaxRunes = 500

// titlePrompt is the prompt template for AI title generation.
const titlePrompt = `Generate a concise title (max 50 characters) for a chat session based on this first message.
The title should capture the main topic or intent.
Return ONLY the title text, no quotes, no explanations, no punctuation at the end.

Message: %s

Title:`

// generateTitleWithAI uses Genkit to generate a session title from user message.
// Returns empty string if generation fails (caller should use fallback).
func (h *Chat) generateTitleWithAI(ctx context.Context, userMessage string) string {
	if h.genkit == nil {
		return ""
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, TitleGenerationTimeout)
	defer cancel()

	// Truncate input to avoid sending very long messages to the AI
	inputRunes := []rune(userMessage)
	if len(inputRunes) > TitleInputMaxRunes {
		userMessage = string(inputRunes[:TitleInputMaxRunes]) + "..."
	}

	response, err := genkit.Generate(ctx, h.genkit,
		ai.WithModelName(TitleGenerationModel),
		ai.WithPrompt(titlePrompt, userMessage),
	)
	if err != nil {
		h.logger.Debug("AI title generation failed, will use truncation fallback",
			"error", err,
		)
		return ""
	}

	title := strings.TrimSpace(response.Text())

	// Validate and truncate if needed
	if title == "" {
		return ""
	}

	// Ensure title is within limits
	titleRunes := []rune(title)
	if len(titleRunes) > TitleMaxLength {
		title = string(titleRunes[:TitleMaxLength-3]) + "..."
	}

	return title
}

// classifyError returns error code and user message based on error type.
// Pure function - no side effects, easily testable.
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

// writeStreamError handles flow errors and sends appropriate SSE error events.
// Per golang-master: Use "write*" prefix for consistency with SSE writer methods.
func (h *Chat) writeStreamError(w SSEWriter, s *streamState, err error) {
	code, message := classifyError(err)
	h.logger.Error("flow execution failed", "error", err, "sessionId", s.sessionID)
	if writeErr := w.WriteError(s.msgID, code, message); writeErr != nil {
		h.logger.Debug("failed to write error event (client may have disconnected)",
			"error", writeErr)
	}
}

// writeFinalMessage sends the final message with OOB swap.
// Per golang-master: Use "write*" prefix.
func (*Chat) writeFinalMessage(ctx context.Context, w SSEWriter, s *streamState, response string) error {
	finalMsg := component.MessageBubble(component.MessageBubbleProps{
		Content: response,
		Role:    "assistant",
	})
	return w.WriteDone(ctx, s.msgID, finalMsg)
}

// processChunk handles a single text chunk, parsing artifacts and streaming content.
// Per rob-pike: Shorter name; "with artifacts" is implementation detail.
// State changes are made directly on streamState receiver.
func (s *streamState) processChunk(ctx context.Context, h *Chat, w SSEWriter, text string) error {
	// Accumulate text
	s.buffer.WriteString(text)

	// Parse for artifacts
	artifact, before, after := parseArtifact(s.buffer.String())

	if artifact == nil {
		// No complete artifact - send safe content
		safe, held := safeSplit(s.buffer.String())
		s.buffer.Reset()
		s.buffer.WriteString(held)
		if safe != "" {
			return w.WriteChunkRaw(s.msgID, html.EscapeString(safe))
		}
		return nil
	}

	// Complete artifact found
	// 1. Send text before artifact
	if before != "" {
		if err := w.WriteChunkRaw(s.msgID, html.EscapeString(before)); err != nil {
			return err
		}
	}

	// 2. Show canvas panel (once)
	// Per htmx-master: WriteCanvasShow BEFORE WriteArtifact
	if !s.canvasShown {
		if err := w.WriteCanvasShow(); err != nil {
			h.logger.Warn("canvas show failed", "error", err)
		}
		s.canvasShown = true
	}

	// 3. Send artifact to canvas panel
	artifactComp := component.ArtifactContent(component.ArtifactContentProps{
		Type:     string(artifact.Type),
		Language: artifact.Language,
		Title:    artifact.Title,
		Content:  artifact.Content,
	})
	if err := w.WriteArtifact(ctx, artifactComp); err != nil {
		return err
	}

	// 4. Reset buffer with remaining text
	s.buffer.Reset()
	s.buffer.WriteString(after)

	return nil
}

// Send handles POST /genui/chat/send (HTMX form submission).
// Supports lazy session creation.
// When pre-session CSRF token is received, creates a new session and returns
// OOB swaps to update the hidden form fields with new session_id and csrf_token.
func (h *Chat) Send(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.logger.Error("failed to parse form", "error", err)
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		http.Error(w, "content is required", http.StatusBadRequest)
		return
	}

	var (
		sessionIDStr string
		newCSRFToken string
		isNewSession bool
		sessionUUID  uuid.UUID
	)

	// Handle CSRF validation with lazy session creation
	if h.sessions != nil {
		csrfToken := r.FormValue("csrf_token")

		if IsPreSessionToken(csrfToken) {
			// Pre-session request: validate pre-session CSRF and create session
			if err := h.sessions.CheckPreSessionCSRF(csrfToken); err != nil {
				h.logger.Warn("pre-session CSRF validation failed", "error", err)
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			// Create new session (lazy creation)
			newSession, err := h.sessions.Store().CreateSession(r.Context(), "", "", "")
			if err != nil {
				h.logger.Error("failed to create session", "error", err)
				http.Error(w, "failed to create session", http.StatusInternalServerError)
				return
			}

			sessionUUID = newSession.ID
			sessionIDStr = sessionUUID.String()
			isNewSession = true

			// Set session cookie
			h.sessions.SetSessionCookie(w, sessionUUID)

			// Update browser URL to reflect new session
			// This enables bookmarking and sharing of the session
			w.Header().Set("HX-Push-Url", "/genui?session_id="+sessionIDStr)

			// Generate new session-bound CSRF token for future requests
			newCSRFToken = h.sessions.NewCSRFToken(sessionUUID)

			h.logger.Info("lazy session created on first message",
				"session_id", sessionIDStr)
		} else {
			// Session-bound request: validate against existing session
			var err error
			sessionUUID, err = h.sessions.ID(r)
			if err != nil {
				h.logger.Warn("session not found", "error", err)
				http.Error(w, "invalid session", http.StatusForbidden)
				return
			}

			if err := h.sessions.CheckCSRF(sessionUUID, csrfToken); err != nil {
				h.logger.Warn("CSRF validation failed", "error", err, "session", sessionUUID)
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			sessionIDStr = sessionUUID.String()
		}
	} else {
		// No sessions configured - use form value or default
		sessionIDStr = r.FormValue("session_id")
		if sessionIDStr == "" {
			sessionIDStr = "default"
		}
	}

	msgID := generateMessageID()

	// 1. Render user message
	userMsg := component.MessageBubble(component.MessageBubbleProps{
		Content: content,
		Role:    "user",
	})
	if err := userMsg.Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render user message", "error", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}

	// 2. Render assistant message shell with scoped SSE connection
	// Pass the user's message (content) so it can be included in the SSE URL
	assistantShell := component.AIMessageStreaming(msgID, sessionIDStr, content)
	if err := assistantShell.Render(r.Context(), w); err != nil {
		h.logger.Error("failed to render assistant shell", "error", err)
		return
	}

	// Include OOB swaps for lazy session creation
	// Updates hidden form fields with new session_id and csrf_token
	if isNewSession && newCSRFToken != "" {
		oobSwaps := component.SessionFieldsOOB(sessionIDStr, newCSRFToken)
		if err := oobSwaps.Render(r.Context(), w); err != nil {
			h.logger.Error("failed to render OOB swaps", "error", err)
			// Non-fatal: main response already sent
		}
	}
}

// Stream handles GET /genui/stream?msgId=X&session_id=Y (SSE endpoint).
// Each assistant message creates its own SSE connection.
// Query is retrieved from database to avoid URL length limits.
func (h *Chat) Stream(w http.ResponseWriter, r *http.Request) {
	msgID := r.URL.Query().Get("msgId")
	sessionID := r.URL.Query().Get("session_id")

	if msgID == "" || sessionID == "" {
		http.Error(w, "missing parameters", http.StatusBadRequest)
		return
	}

	// For now, get query from URL (will be enhanced to fetch from DB later)
	query := r.URL.Query().Get("query")
	if query == "" {
		// Fallback: simulation mode doesn't require query
		query = "Hello"
	}

	sseWriter, err := h.sseWriterFn(w)
	if err != nil {
		h.logger.Error("SSE not supported", "error", err)
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Apply timeout to prevent zombie connections
	ctx, cancel := context.WithTimeout(r.Context(), SSETimeout)
	defer cancel()

	// Use real Flow if available, otherwise simulate
	if h.flow != nil {
		h.streamWithFlow(ctx, sseWriter, msgID, sessionID, query)
	} else {
		h.simulateStreaming(ctx, sseWriter, msgID, sessionID, query)
	}
}

// streamWithFlow uses the real chat.Flow to generate AI responses.
// Refactored to reduce cyclomatic complexity.
// Uses streamState struct and helper functions for cleaner code.
func (h *Chat) streamWithFlow(ctx context.Context, w SSEWriter, msgID, sessionID, query string) {
	// Initialize stream state
	state := &streamState{
		msgID:     msgID,
		sessionID: sessionID,
	}

	// BUG #1 FIX: Get canvas mode from DATABASE (not cookie)
	var canvasEnabled bool
	if h.sessions != nil {
		sessionUUID, parseErr := uuid.Parse(sessionID)
		if parseErr != nil {
			h.logger.Warn("invalid session ID format, defaulting canvas to false",
				"session_id", sessionID, "error", parseErr)
		} else {
			session, getErr := h.sessions.Store().GetSession(ctx, sessionUUID)
			if getErr == nil {
				canvasEnabled = session.CanvasMode
			} else {
				h.logger.Warn("failed to get session for canvas mode", "error", getErr)
			}
		}
	}

	input := chat.Input{
		Query:         query,
		SessionID:     sessionID,
		CanvasEnabled: canvasEnabled, // BUG #1 FIX: Now properly set!
	}

	h.logger.Debug("starting stream",
		"sessionId", sessionID,
		"canvasEnabled", canvasEnabled)

	var (
		finalOutput chat.Output
		streamErr   error
	)

	// Iterate over streaming Flow results using Go 1.23 range-over-func
	for streamValue, err := range h.flow.Stream(ctx, input) {
		// Check for context cancellation
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

		// Process partial text chunks with artifact parsing
		if streamValue.Stream.Text != "" {
			if err := state.processChunk(ctx, h, w, streamValue.Stream.Text); err != nil {
				h.logger.Error("failed to process chunk", "error", err)
				return
			}
		}
	}

	// Handle errors using helper function
	if streamErr != nil {
		h.writeStreamError(w, state, streamErr)
		return
	}

	// Flush any remaining buffered content
	if state.buffer.Len() > 0 {
		if err := w.WriteChunkRaw(msgID, html.EscapeString(state.buffer.String())); err != nil {
			h.logger.Error("failed to flush buffer", "error", err)
		}
	}

	// Auto-generate session title BEFORE final message
	// IMPORTANT: Must be called before WriteDone because WriteDone sends "done" event
	// which triggers sse-close="done" on client, closing the SSE connection.
	// If called after, WriteSidebarRefresh would write to a closed connection.
	h.maybeGenerateTitle(ctx, w, sessionID, query)

	// Send final complete message with OOB swap (closes SSE connection)
	if err := h.writeFinalMessage(ctx, w, state, finalOutput.Response); err != nil {
		h.logger.Error("failed to send done", "error", err)
	}
}

// maybeGenerateTitle generates a session title if one doesn't exist.
// Sync approach - generates title after first AI response.
// Currently uses truncation fallback; Genkit-based generation is a future enhancement.
func (h *Chat) maybeGenerateTitle(ctx context.Context, w SSEWriter, sessionID, userMessage string) {
	if h.sessions == nil {
		return
	}

	sessionUUID, parseErr := uuid.Parse(sessionID)
	if parseErr != nil {
		h.logger.Warn("invalid session ID for title generation", "session_id", sessionID)
		return
	}

	// Check if session already has a title
	session, getErr := h.sessions.Store().GetSession(ctx, sessionUUID)
	if getErr != nil {
		h.logger.Warn("failed to get session for title check", "error", getErr)
		return
	}

	// Only generate title if it's empty (first message scenario)
	if session.Title != "" {
		return
	}

	// Generate title using AI (with truncation fallback)
	// Genkit AI title generation
	title := h.generateTitleWithAI(ctx, userMessage)
	if title == "" {
		// Fallback to truncation if AI generation fails or is unavailable
		title = truncateForTitle(userMessage)
		h.logger.Debug("using truncation fallback for title", "session_id", sessionID)
	}

	// Update session title in database
	if err := h.sessions.Store().UpdateSessionTitle(ctx, sessionUUID, title); err != nil {
		h.logger.Error("failed to update session title",
			"error", err,
			"session_id", sessionID,
		)
		return
	}

	h.logger.Info("auto-generated session title",
		"session_id", sessionID,
		"title", title,
	)

	// Trigger sidebar refresh via SSE
	if err := w.WriteSidebarRefresh(sessionID, title); err != nil {
		h.logger.Debug("failed to send sidebar refresh (client may have disconnected)",
			"error", err,
		)
	}
}

// simulateStreaming is a placeholder for testing without real Flow.
// Used when flow is nil (simulation mode).
func (h *Chat) simulateStreaming(ctx context.Context, w SSEWriter, msgID, sessionID, query string) {
	response := fmt.Sprintf("I received your message: %q. This is a simulated response that will be replaced with actual AI streaming.", query)
	words := strings.Fields(response)

	var fullContent strings.Builder
	for i, word := range words {
		select {
		case <-ctx.Done():
			h.logContextDone(ctx, msgID)
			return
		default:
		}

		if i > 0 {
			fullContent.WriteString(" ")
		}
		fullContent.WriteString(word)

		// Use WriteChunkRaw with escaped content (simulation mode)
		if err := w.WriteChunkRaw(msgID, html.EscapeString(fullContent.String())); err != nil {
			h.logger.Error("failed to send chunk", "error", err)
			return
		}

		// Simulate typing delay
		time.Sleep(50 * time.Millisecond)
	}

	// Auto-generate session title BEFORE final message
	// IMPORTANT: Must be called before WriteDone (see streamWithFlow comment).
	h.maybeGenerateTitle(ctx, w, sessionID, query)

	// Send final complete message with OOB swap (closes SSE connection)
	finalMsg := component.MessageBubble(component.MessageBubbleProps{
		Content: fullContent.String(),
		Role:    "assistant",
	})
	if err := w.WriteDone(ctx, msgID, finalMsg); err != nil {
		h.logger.Error("failed to send done", "error", err)
	}
}

func generateMessageID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// logContextDone logs the appropriate message based on context cancellation reason.
func (h *Chat) logContextDone(ctx context.Context, msgID string) {
	if ctx.Err() == context.DeadlineExceeded {
		h.logger.Warn("SSE connection timeout", "msgId", msgID, "timeout", SSETimeout)
	} else {
		h.logger.Info("client disconnected", "msgId", msgID)
	}
}
