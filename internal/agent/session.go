// Package agent provides session management functionality for the AI agent.
//
// This file contains session-related methods:
//   - loadCurrentSession: Load session from local state
//   - NewSession: Create new conversation session
//   - SwitchSession: Switch to existing session
//   - GetCurrentSession: Get current session info
package agent

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/session"
)

// loadCurrentSession loads the session specified in local state file.
// Called automatically by New().
// Loading failure is not fatal - Agent continues with empty history.
func (a *Agent) loadCurrentSession(ctx context.Context) error {
	// Read local state file
	sessionID, err := session.LoadCurrentSessionID()
	if err != nil {
		return fmt.Errorf("failed to load current session ID: %w", err)
	}

	if sessionID == nil {
		// No current session - this is normal
		return nil
	}

	// Load session messages from database
	messages, err := a.sessionStore.GetMessages(ctx, *sessionID, a.config.MaxHistoryMessages, 0)
	if err != nil {
		return fmt.Errorf("failed to load session messages: %w", err)
	}

	// Convert session.Message to ai.Message
	var aiMessages []*ai.Message
	for _, msg := range messages {
		aiMsg := &ai.Message{
			Role:    ai.Role(msg.Role),
			Content: msg.Content,
		}
		aiMessages = append(aiMessages, aiMsg)
	}

	// Update Agent state
	a.messagesMu.Lock()
	a.messages = aiMessages
	a.currentSessionID = sessionID
	a.messagesMu.Unlock()

	a.logger.Info("loaded session",
		"session_id", *sessionID,
		"message_count", len(aiMessages))

	return nil
}

// NewSession creates a new conversation session and switches to it.
// Clears current conversation history and starts fresh.
//
// Parameters:
//   - title: Session title (can be empty)
//
// Returns:
//   - *session.Session: Created session
//   - error: If creation fails
func (a *Agent) NewSession(ctx context.Context, title string) (*session.Session, error) {
	// Create new session in database
	newSession, err := a.sessionStore.CreateSession(ctx, title, a.config.ModelName, a.systemPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Save to local state file
	if err := session.SaveCurrentSessionID(newSession.ID); err != nil {
		return nil, fmt.Errorf("failed to save current session: %w", err)
	}

	// Clear current history
	a.messagesMu.Lock()
	a.messages = []*ai.Message{}
	a.currentSessionID = &newSession.ID
	a.messagesMu.Unlock()

	a.logger.Info("created new session",
		"session_id", newSession.ID,
		"title", newSession.Title)

	return newSession, nil
}

// SwitchSession switches to an existing session.
// Loads the session's conversation history from database.
//
// Parameters:
//   - sessionID: UUID of the session to switch to
//
// Returns:
//   - error: If switching fails
func (a *Agent) SwitchSession(ctx context.Context, sessionID uuid.UUID) error {
	// Save to local state file
	if err := session.SaveCurrentSessionID(sessionID); err != nil {
		return fmt.Errorf("failed to save current session: %w", err)
	}

	// Load session (same logic as loadCurrentSession)
	return a.loadCurrentSession(ctx)
}

// GetCurrentSession retrieves the current session information.
//
// Returns:
//   - *session.Session: Current session
//   - error: If no active session or retrieval fails
func (a *Agent) GetCurrentSession(ctx context.Context) (*session.Session, error) {
	if a.currentSessionID == nil {
		return nil, fmt.Errorf("no active session")
	}

	return a.sessionStore.GetSession(ctx, *a.currentSessionID)
}
