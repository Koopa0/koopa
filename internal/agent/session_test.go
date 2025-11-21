package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/session"
)

// ============================================================================
// Session Management Function Tests
// ============================================================================
// Tests in this file cover session-related Agent methods:
//   - NewSession: Create new sessions
//   - SwitchSession: Switch between existing sessions
//   - GetCurrentSession: Retrieve the active session
//
// These tests verify session lifecycle, state management, and error handling.
// ============================================================================

// TestNewSession_Success verifies successful session creation.
// Ensures:
//   - Session is created with correct title
//   - Conversation history is cleared
//   - Session ID is saved to state
//   - CreateSession is called with correct parameters
func TestNewSession_Success(t *testing.T) {
	mockStore := &mockSessionStore{}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("old message")}},
		},
		logger: slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.NewSession(ctx, "Test Session Title")
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
		return
	}
	if session.Title != "Test Session Title" {
		t.Errorf("expected title 'Test Session Title', got %q", session.Title)
	}

	// Verify history was cleared
	if len(agent.messages) != 0 {
		t.Errorf("expected history to be cleared, got %d messages", len(agent.messages))
	}

	// Verify CreateSession was called
	if !mockStore.createCalled {
		t.Error("expected CreateSession to be called")
	}

	// Verify currentSessionID was set
	if agent.currentSessionID == nil {
		t.Error("expected currentSessionID to be set")
	} else if *agent.currentSessionID != session.ID {
		t.Errorf("expected currentSessionID %v, got %v", session.ID, *agent.currentSessionID)
	}
}

// TestNewSession_CreateFails verifies error handling when CreateSession fails.
func TestNewSession_CreateFails(t *testing.T) {
	mockStore := &mockSessionStore{
		createSessionFunc: func(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
			return nil, errors.New("database error")
		},
	}

	agent := &Agent{
		config:       &config.Config{ModelName: "test-model"},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		logger:       slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.NewSession(ctx, "Test Title")

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if !errors.Is(err, errors.New("database error")) && err.Error() != "failed to create session: database error" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestNewSession_ClearsHistory verifies that NewSession clears existing conversation history.
func TestNewSession_ClearsHistory(t *testing.T) {
	mockStore := &mockSessionStore{}

	// Create agent with 3 messages in history
	agent := &Agent{
		config:       &config.Config{ModelName: "test-model"},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages: []*ai.Message{
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("message 1")}},
			{Role: ai.RoleModel, Content: []*ai.Part{ai.NewTextPart("response 1")}},
			{Role: ai.RoleUser, Content: []*ai.Part{ai.NewTextPart("message 2")}},
		},
		logger: slog.Default(),
	}

	if len(agent.messages) != 3 {
		t.Fatalf("setup failed: expected 3 messages, got %d", len(agent.messages))
	}

	ctx := context.Background()
	_, err := agent.NewSession(ctx, "New Session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all history was cleared
	if len(agent.messages) != 0 {
		t.Errorf("expected empty history, got %d messages", len(agent.messages))
	}
}

// TestSwitchSession_Success verifies successful session switching.
func TestSwitchSession_Success(t *testing.T) {
	testSessionID := uuid.New()

	// Create mock messages to return from GetMessages
	mockMessages := []*session.Message{
		{
			Role:    string(ai.RoleUser),
			Content: []*ai.Part{ai.NewTextPart("previous message")},
		},
	}

	mockStore := &mockSessionStore{
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
			if sessionID != testSessionID {
				t.Errorf("expected session ID %v, got %v", testSessionID, sessionID)
			}
			return mockMessages, nil
		},
	}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		messages:     []*ai.Message{},
		logger:       slog.Default(),
	}

	// First, save the session ID to local state
	if err := session.SaveCurrentSessionID(testSessionID); err != nil {
		t.Fatalf("failed to save session ID: %v", err)
	}

	ctx := context.Background()
	err := agent.SwitchSession(ctx, testSessionID)
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify GetMessages was called
	if !mockStore.getMessagesCalled {
		t.Error("expected GetMessages to be called")
	}

	// Verify messages were loaded
	if len(agent.messages) != 1 {
		t.Errorf("expected 1 message loaded, got %d", len(agent.messages))
	}

	// Verify currentSessionID was set
	if agent.currentSessionID == nil {
		t.Error("expected currentSessionID to be set")
	} else if *agent.currentSessionID != testSessionID {
		t.Errorf("expected currentSessionID %v, got %v", testSessionID, *agent.currentSessionID)
	}
}

// TestSwitchSession_GetMessagesFails verifies error handling when GetMessages fails.
func TestSwitchSession_GetMessagesFails(t *testing.T) {
	testSessionID := uuid.New()

	mockStore := &mockSessionStore{
		getMessagesFunc: func(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
			return nil, errors.New("database connection failed")
		},
	}

	agent := &Agent{
		config: &config.Config{
			ModelName:          "test-model",
			MaxHistoryMessages: 10,
		},
		sessionStore: mockStore,
		systemPrompt: "test prompt",
		logger:       slog.Default(),
	}

	// Save the session ID to local state
	if err := session.SaveCurrentSessionID(testSessionID); err != nil {
		t.Fatalf("failed to save session ID: %v", err)
	}

	ctx := context.Background()
	err := agent.SwitchSession(ctx, testSessionID)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify error message contains "failed to load session messages"
	if err.Error() != "failed to load session messages: database connection failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestGetCurrentSession_NoSession verifies error when no active session exists.
func TestGetCurrentSession_NoSession(t *testing.T) {
	mockStore := &mockSessionStore{}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: nil, // No active session
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if err.Error() != "no active session" {
		t.Errorf("expected error 'no active session', got %q", err.Error())
	}

	// Verify GetSession was NOT called
	if mockStore.getCalled {
		t.Error("GetSession should not be called when currentSessionID is nil")
	}
}

// TestGetCurrentSession_Success verifies successful retrieval of current session.
func TestGetCurrentSession_Success(t *testing.T) {
	testSessionID := uuid.New()
	expectedSession := &session.Session{
		ID:    testSessionID,
		Title: "Current Session",
	}

	mockStore := &mockSessionStore{
		getSessionFunc: func(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
			if sessionID != testSessionID {
				t.Errorf("expected session ID %v, got %v", testSessionID, sessionID)
			}
			return expectedSession, nil
		},
	}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: &testSessionID,
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)
	// Verify success
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
		return
	}
	if session.ID != testSessionID {
		t.Errorf("expected session ID %v, got %v", testSessionID, session.ID)
	}
	if session.Title != "Current Session" {
		t.Errorf("expected title 'Current Session', got %q", session.Title)
	}

	// Verify GetSession was called
	if !mockStore.getCalled {
		t.Error("expected GetSession to be called")
	}
}

// TestGetCurrentSession_GetSessionFails verifies error handling when GetSession fails.
func TestGetCurrentSession_GetSessionFails(t *testing.T) {
	testSessionID := uuid.New()

	mockStore := &mockSessionStore{
		getSessionFunc: func(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
			return nil, errors.New("session not found")
		},
	}

	agent := &Agent{
		config:           &config.Config{ModelName: "test-model"},
		sessionStore:     mockStore,
		currentSessionID: &testSessionID,
		logger:           slog.Default(),
	}

	ctx := context.Background()
	session, err := agent.GetCurrentSession(ctx)

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if session != nil {
		t.Errorf("expected nil session, got %v", session)
	}

	// Verify error message
	if err.Error() != "session not found" {
		t.Errorf("unexpected error message: %v", err)
	}
}
