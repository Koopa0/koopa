// Package agent provides conversation history management functionality.
//
// This file contains history-related methods:
//   - ClearHistory: Clear conversation history
//   - HistoryLength: Get history length
//   - trimHistoryIfNeeded: Limit history size (sliding window)
//   - vectorizeConversationTurn: Vectorize and store conversation turns
//   - Helper functions for vectorization
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/knowledge"
)

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	a.messagesMu.Lock()
	defer a.messagesMu.Unlock()
	a.messages = []*ai.Message{}
}

// HistoryLength retrieves the conversation history length
func (a *Agent) HistoryLength() int {
	a.messagesMu.RLock()
	defer a.messagesMu.RUnlock()
	return len(a.messages)
}

// trimHistoryIfNeeded checks and limits conversation history length (sliding window mechanism)
// Strategy: keep most recent N messages
func (a *Agent) trimHistoryIfNeeded() {
	maxMessages := a.config.MaxHistoryMessages

	// 0 means unlimited
	if maxMessages <= 0 {
		// MEMORY WARNING: Monitor for potential memory leaks when unlimited
		if len(a.messages) > 1000 {
			// Estimate memory usage (rough estimate: ~1KB per message)
			estimatedMB := len(a.messages) / 1024
			slog.Warn("conversation history growing large with unlimited mode",
				"message_count", len(a.messages),
				"estimated_memory_mb", estimatedMB,
				"max_history_messages", maxMessages,
				"suggestion", "consider setting max_history_messages to limit memory usage")
		}
		return
	}

	// If history exceeds limit, keep only most recent maxMessages
	// Use max() to ensure non-negative start index
	a.messages = a.messages[max(0, len(a.messages)-int(maxMessages)):]
}

// ============================================================================
// Conversation History Vectorization
// ============================================================================

// extractTextFromMessage extracts plain text content from an ai.Message.
// Used to build conversation turn content for vectorization.
func (a *Agent) extractTextFromMessage(msg *ai.Message) string {
	var sb strings.Builder
	for _, part := range msg.Content {
		if part.IsText() {
			sb.WriteString(part.Text)
		}
	}
	return sb.String()
}

// extractToolInfo extracts tool name and result from a tool response message.
// Returns empty strings if no tool response is found.
// Handles multiple output types: string, nil, map, array, etc.
func (a *Agent) extractToolInfo(msg *ai.Message) (toolName string, result string) {
	for _, part := range msg.Content {
		if part.ToolResponse != nil {
			toolName = part.ToolResponse.Name

			// Handle different output types
			switch output := part.ToolResponse.Output.(type) {
			case string:
				result = output
			case nil:
				result = ""
			default:
				// For non-string types, marshal to JSON
				if jsonBytes, err := json.Marshal(output); err == nil {
					result = string(jsonBytes)
				}
			}
			return
		}
	}
	return "", ""
}

// getCurrentSessionID returns the current session ID for vectorization.
// Returns "ephemeral-session" when no session is active.
// This ensures all conversations are vectorizable and searchable via searchHistory.
func (a *Agent) getCurrentSessionID() string {
	if a.currentSessionID == nil {
		return "ephemeral-session"
	}

	return a.currentSessionID.String()
}

// buildTurnContent constructs the text content for a conversation turn.
// Returns: (content, toolCount, error)
// Boundary cases: returns error for incomplete turns (no assistant or no user).
func (a *Agent) buildTurnContent(messages []*ai.Message) (string, int, error) {
	if len(messages) < 2 {
		return "", 0, fmt.Errorf("not enough messages for a turn (need 2+, have %d)", len(messages))
	}

	// From back to front, find complete User → ... → Assistant sequence
	var currentTurn []*ai.Message
	foundAssistant := false
	foundUser := false

	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		currentTurn = append([]*ai.Message{msg}, currentTurn...)

		if msg.Role == ai.RoleModel {
			foundAssistant = true
		}

		if foundAssistant && msg.Role == ai.RoleUser {
			foundUser = true
			break
		}
	}

	if !foundAssistant || !foundUser {
		return "", 0, fmt.Errorf("incomplete turn: foundAssistant=%v, foundUser=%v",
			foundAssistant, foundUser)
	}

	// Build content string
	var sb strings.Builder
	toolCount := 0
	var userMsg, assistantMsg *ai.Message
	var toolMessages []*ai.Message

	// Identify message types in current turn
	for _, msg := range currentTurn {
		switch msg.Role {
		case ai.RoleUser:
			userMsg = msg
		case ai.RoleModel:
			assistantMsg = msg
		case ai.RoleTool:
			toolMessages = append(toolMessages, msg)
		}
	}

	// User query
	if userMsg != nil {
		sb.WriteString("User: ")
		sb.WriteString(a.extractTextFromMessage(userMsg))
		sb.WriteString("\n\n")
	}

	// Tool actions (if any)
	if len(toolMessages) > 0 {
		sb.WriteString("Actions taken:\n")
		for _, toolMsg := range toolMessages {
			toolName, result := a.extractToolInfo(toolMsg)
			if toolName != "" {
				sb.WriteString(fmt.Sprintf("- Used %s\n", toolName))
				sb.WriteString(fmt.Sprintf("  Result: %s\n", truncateString(result, 200)))
				toolCount++
			}
		}
		sb.WriteString("\n")
	}

	// Assistant response
	if assistantMsg != nil {
		sb.WriteString("Assistant: ")
		sb.WriteString(a.extractTextFromMessage(assistantMsg))
	}

	return sb.String(), toolCount, nil
}

// calculateTurnNumber calculates the turn number for the current session.
// Uses knowledge.Store.Count() to dynamically calculate turn number, avoiding concurrent state management.
// Returns 0 on error (first turn as fallback).
func (a *Agent) calculateTurnNumber(ctx context.Context, sessionID string) int {
	// Query knowledge store for existing conversation turns in this session
	count, err := a.knowledgeStore.Count(ctx, map[string]string{
		"source_type": "conversation",
		"session_id":  sessionID,
	})

	if err != nil {
		a.logger.Warn("failed to calculate turn number, using 0 as fallback",
			"session_id", sessionID,
			"error", err)
		return 0
	}

	// Next turn number is count + 1
	return count + 1
}

// isRetriableError determines if an error is transient and should be retried.
// Uses Go best practices: type assertion via errors.As and errors.Is.
func isRetriableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded (timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for context cancelled (not retriable - user cancelled)
	if errors.Is(err, context.Canceled) {
		return false
	}

	// For other errors, consider non-retriable by default
	// Can be extended later if specific error types need retry
	return false
}

// vectorizeConversationTurn vectorizes the latest conversation turn and stores it in knowledge store.
// This method is called after each complete turn (User → Assistant) in Execute().
// Features: 3-retry mechanism with exponential backoff, complete boundary checking.
func (a *Agent) vectorizeConversationTurn(ctx context.Context) error {
	// Step 1: Build turn content (with boundary checks)
	a.messagesMu.RLock()
	messages := a.messages
	a.messagesMu.RUnlock()

	content, toolCount, err := a.buildTurnContent(messages)
	if err != nil {
		return fmt.Errorf("buildTurnContent failed: %w", err)
	}

	// Step 2: Get session ID (supports ephemeral-session)
	sessionID := a.getCurrentSessionID()

	// Step 3: Calculate turn number
	turnNumber := a.calculateTurnNumber(ctx, sessionID)

	// Step 4: Build metadata
	metadata := map[string]string{
		"source_type": "conversation",
		"session_id":  sessionID,
		"timestamp":   time.Now().Format(time.RFC3339),
		"turn_number": strconv.Itoa(turnNumber),
		"tool_count":  strconv.Itoa(toolCount),
	}

	// Step 5: Create document
	doc := knowledge.Document{
		Content:  content,
		Metadata: metadata,
	}

	// Step 6: Store with 3-retry mechanism
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		// Create timeout context for this attempt
		storeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = a.knowledgeStore.Add(storeCtx, doc)
		cancel()

		if err == nil {
			// Success
			a.logger.Info("conversation turn vectorized",
				"session_id", sessionID,
				"turn_number", turnNumber,
				"tool_count", toolCount,
				"content_length", len(content))
			return nil
		}

		lastErr = err

		// Check if error is retriable
		if !isRetriableError(err) {
			// Non-retriable error, fail immediately
			a.logger.Error("non-retriable error in vectorization",
				"attempt", attempt+1,
				"error", err)
			break
		}

		// Retriable error: log and retry with exponential backoff
		a.logger.Warn("vectorization failed, retrying",
			"attempt", attempt+1,
			"error", err)

		if attempt < 2 { // Don't sleep after last attempt
			backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
			time.Sleep(backoff)
		}
	}

	// All retries failed
	return fmt.Errorf("knowledge store add failed after 3 attempts: %w", lastErr)
}
