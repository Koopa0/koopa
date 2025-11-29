package session

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// mockSessionQuerier implements SessionQuerier for testing
type mockSessionQuerier struct {
	// Error configuration
	createSessionErr          error
	getSessionErr             error
	listSessionsErr           error
	updateSessionUpdatedAtErr error
	deleteSessionErr          error
	lockSessionErr            error
	addMessageErr             error
	getMessagesErr            error
	getMaxSequenceNumberErr   error

	// Branch-related errors
	addMessageWithBranchErr   error
	getMessagesByBranchErr    error
	getMaxSequenceByBranchErr error
	countMessagesByBranchErr  error
	deleteMessagesByBranchErr error

	// Return values
	createSessionResult          sqlc.Session
	getSessionResult             sqlc.Session
	listSessionsResult           []sqlc.Session
	getMessagesResult            []sqlc.SessionMessage
	getMaxSequenceNumberResult   any
	getMessagesByBranchResult    []sqlc.SessionMessage
	getMaxSequenceByBranchResult int32
	countMessagesByBranchResult  int32

	// Call tracking
	createSessionCalls          int
	getSessionCalls             int
	listSessionsCalls           int
	updateSessionUpdatedAtCalls int
	deleteSessionCalls          int
	lockSessionCalls            int
	addMessageCalls             int
	getMessagesCalls            int
	getMaxSequenceNumberCalls   int

	// Branch-related call tracking
	addMessageWithBranchCalls   int
	getMessagesByBranchCalls    int
	getMaxSequenceByBranchCalls int
	countMessagesByBranchCalls  int
	deleteMessagesByBranchCalls int

	lastCreateParams      sqlc.CreateSessionParams
	lastGetSessionID      pgtype.UUID
	lastListParams        sqlc.ListSessionsParams
	lastUpdateParams      sqlc.UpdateSessionUpdatedAtParams
	lastDeleteSessionID   pgtype.UUID
	lastLockSessionID     pgtype.UUID
	lastAddMessageParams  []sqlc.AddMessageParams
	lastGetMessagesParams sqlc.GetMessagesParams
	lastMaxSeqSessionID   pgtype.UUID

	// Branch-related last params
	lastAddMessageWithBranchParams []sqlc.AddMessageWithBranchParams
	lastGetMessagesByBranchParams  sqlc.GetMessagesByBranchParams
}

func (m *mockSessionQuerier) CreateSession(ctx context.Context, arg sqlc.CreateSessionParams) (sqlc.Session, error) {
	m.createSessionCalls++
	m.lastCreateParams = arg
	if m.createSessionErr != nil {
		return sqlc.Session{}, m.createSessionErr
	}
	return m.createSessionResult, nil
}

func (m *mockSessionQuerier) GetSession(ctx context.Context, id pgtype.UUID) (sqlc.Session, error) {
	m.getSessionCalls++
	m.lastGetSessionID = id
	if m.getSessionErr != nil {
		return sqlc.Session{}, m.getSessionErr
	}
	return m.getSessionResult, nil
}

func (m *mockSessionQuerier) ListSessions(ctx context.Context, arg sqlc.ListSessionsParams) ([]sqlc.Session, error) {
	m.listSessionsCalls++
	m.lastListParams = arg
	if m.listSessionsErr != nil {
		return nil, m.listSessionsErr
	}
	return m.listSessionsResult, nil
}

func (m *mockSessionQuerier) UpdateSessionUpdatedAt(ctx context.Context, arg sqlc.UpdateSessionUpdatedAtParams) error {
	m.updateSessionUpdatedAtCalls++
	m.lastUpdateParams = arg
	return m.updateSessionUpdatedAtErr
}

func (m *mockSessionQuerier) DeleteSession(ctx context.Context, id pgtype.UUID) error {
	m.deleteSessionCalls++
	m.lastDeleteSessionID = id
	return m.deleteSessionErr
}

func (m *mockSessionQuerier) LockSession(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error) {
	m.lockSessionCalls++
	m.lastLockSessionID = id
	if m.lockSessionErr != nil {
		return pgtype.UUID{}, m.lockSessionErr
	}
	return id, nil
}

func (m *mockSessionQuerier) AddMessage(ctx context.Context, arg sqlc.AddMessageParams) error {
	m.addMessageCalls++
	m.lastAddMessageParams = append(m.lastAddMessageParams, arg)
	return m.addMessageErr
}

func (m *mockSessionQuerier) GetMessages(ctx context.Context, arg sqlc.GetMessagesParams) ([]sqlc.SessionMessage, error) {
	m.getMessagesCalls++
	m.lastGetMessagesParams = arg
	if m.getMessagesErr != nil {
		return nil, m.getMessagesErr
	}
	return m.getMessagesResult, nil
}

func (m *mockSessionQuerier) GetMaxSequenceNumber(ctx context.Context, sessionID pgtype.UUID) (int32, error) {
	m.getMaxSequenceNumberCalls++
	m.lastMaxSeqSessionID = sessionID
	if m.getMaxSequenceNumberErr != nil {
		return 0, m.getMaxSequenceNumberErr
	}
	if m.getMaxSequenceNumberResult == nil {
		return 0, nil
	}
	// Convert stored result to int32
	switch v := m.getMaxSequenceNumberResult.(type) {
	case int32:
		return v, nil
	case int:
		return int32(v), nil
	case int64:
		return int32(v), nil
	default:
		return 0, nil
	}
}

// Branch-related methods

func (m *mockSessionQuerier) AddMessageWithBranch(ctx context.Context, arg sqlc.AddMessageWithBranchParams) error {
	m.addMessageWithBranchCalls++
	m.lastAddMessageWithBranchParams = append(m.lastAddMessageWithBranchParams, arg)
	return m.addMessageWithBranchErr
}

func (m *mockSessionQuerier) GetMessagesByBranch(ctx context.Context, arg sqlc.GetMessagesByBranchParams) ([]sqlc.SessionMessage, error) {
	m.getMessagesByBranchCalls++
	m.lastGetMessagesByBranchParams = arg
	if m.getMessagesByBranchErr != nil {
		return nil, m.getMessagesByBranchErr
	}
	return m.getMessagesByBranchResult, nil
}

func (m *mockSessionQuerier) GetMaxSequenceByBranch(ctx context.Context, arg sqlc.GetMaxSequenceByBranchParams) (int32, error) {
	m.getMaxSequenceByBranchCalls++
	if m.getMaxSequenceByBranchErr != nil {
		return 0, m.getMaxSequenceByBranchErr
	}
	return m.getMaxSequenceByBranchResult, nil
}

func (m *mockSessionQuerier) CountMessagesByBranch(ctx context.Context, arg sqlc.CountMessagesByBranchParams) (int32, error) {
	m.countMessagesByBranchCalls++
	if m.countMessagesByBranchErr != nil {
		return 0, m.countMessagesByBranchErr
	}
	return m.countMessagesByBranchResult, nil
}

func (m *mockSessionQuerier) DeleteMessagesByBranch(ctx context.Context, arg sqlc.DeleteMessagesByBranchParams) error {
	m.deleteMessagesByBranchCalls++
	return m.deleteMessagesByBranchErr
}

// ============================================================================
// Tests
// ============================================================================

func TestNew(t *testing.T) {
	t.Run("creates store with custom logger", func(t *testing.T) {
		logger := slog.Default()
		querier := &mockSessionQuerier{}

		store := New(querier, nil, logger)

		if store == nil {
			t.Fatal("expected non-nil store")
			return
		}
		if store.querier != querier {
			t.Error("expected querier to be set")
		}
		if store.logger != logger {
			t.Error("expected logger to be set")
		}
	})

	t.Run("uses default logger when nil provided", func(t *testing.T) {
		querier := &mockSessionQuerier{}

		store := New(querier, nil, nil)

		if store == nil {
			t.Fatal("expected non-nil store")
			return
		}
		if store.logger == nil {
			t.Error("expected default logger to be set")
		}
	})
}

func TestStore_CreateSession(t *testing.T) {
	tests := []struct {
		name          string
		title         string
		modelName     string
		systemPrompt  string
		mockResult    sqlc.Session
		mockErr       error
		wantErr       bool
		wantCallCount int
	}{
		{
			name:         "successful creation with all fields",
			title:        "Test Session",
			modelName:    "gemini-2.5-pro",
			systemPrompt: "You are a helpful assistant",
			mockResult: sqlc.Session{
				ID:           uuidToPgUUID(uuid.New()),
				Title:        strPtr("Test Session"),
				ModelName:    strPtr("gemini-2.5-pro"),
				SystemPrompt: strPtr("You are a helpful assistant"),
				CreatedAt:    timestamptz(time.Now()),
				UpdatedAt:    timestamptz(time.Now()),
				MessageCount: int32Ptr(0),
			},
			wantCallCount: 1,
		},
		{
			name:         "successful creation with empty optional fields",
			title:        "",
			modelName:    "",
			systemPrompt: "",
			mockResult: sqlc.Session{
				ID:           uuidToPgUUID(uuid.New()),
				CreatedAt:    timestamptz(time.Now()),
				UpdatedAt:    timestamptz(time.Now()),
				MessageCount: int32Ptr(0),
			},
			wantCallCount: 1,
		},
		{
			name:          "database error",
			title:         "Test",
			mockErr:       errors.New("database connection failed"),
			wantErr:       true,
			wantCallCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				createSessionResult: tt.mockResult,
				createSessionErr:    tt.mockErr,
			}
			store := New(querier, nil, slog.Default())

			session, err := store.CreateSession(context.Background(), tt.title, tt.modelName, tt.systemPrompt)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if querier.createSessionCalls != tt.wantCallCount {
				t.Errorf("CreateSession() calls = %d, want %d", querier.createSessionCalls, tt.wantCallCount)
			}

			if !tt.wantErr {
				if session == nil {
					t.Error("expected non-nil session")
					return
				}
				if tt.title != "" && session.Title != tt.title {
					t.Errorf("session.Title = %v, want %v", session.Title, tt.title)
				}
			}
		})
	}
}

func TestStore_AddMessages(t *testing.T) {
	sessionID := uuid.New()
	testParts := []*ai.Part{ai.NewTextPart("Hello, world!")}

	t.Run("handles empty message slice", func(t *testing.T) {
		// Empty messages don't require pool (early return)
		store := New(&mockSessionQuerier{}, nil, slog.Default())
		err := store.AddMessages(context.Background(), sessionID, []*Message{})
		if err != nil {
			t.Errorf("AddMessages() with empty slice should not error, got: %v", err)
		}
	})

	t.Run("requires database pool for non-empty messages", func(t *testing.T) {
		// AddMessages now requires a pool for transactional operations
		// This test verifies the error message when pool is nil
		store := New(&mockSessionQuerier{}, nil, slog.Default())
		messages := []*Message{
			{
				SessionID: sessionID,
				Role:      "user",
				Content:   testParts,
			},
		}

		err := store.AddMessages(context.Background(), sessionID, messages)
		if err == nil {
			t.Error("AddMessages() should error when pool is nil")
		}
		if err != nil && !strings.Contains(err.Error(), "database pool required") {
			t.Errorf("AddMessages() error should mention 'database pool required', got: %v", err)
		}
	})

	// Note: Full transactional testing is done in integration_test.go
	// which uses a real database connection via testutil.SetupTestDB
}

func TestStore_GetMessages(t *testing.T) {
	sessionID := uuid.New()
	testContent := []*ai.Part{ai.NewTextPart("Test message")}
	contentJSON, _ := json.Marshal(testContent)

	tests := []struct {
		name         string
		limit        int32
		offset       int32
		mockMessages []sqlc.SessionMessage
		mockErr      error
		wantCount    int
		wantErr      bool
	}{
		{
			name:   "successfully retrieves messages",
			limit:  10,
			offset: 0,
			mockMessages: []sqlc.SessionMessage{
				{
					ID:             uuidToPgUUID(uuid.New()),
					SessionID:      uuidToPgUUID(sessionID),
					Role:           "user",
					Content:        contentJSON,
					SequenceNumber: 1,
					CreatedAt:      timestamptz(time.Now()),
				},
				{
					ID:             uuidToPgUUID(uuid.New()),
					SessionID:      uuidToPgUUID(sessionID),
					Role:           "model",
					Content:        contentJSON,
					SequenceNumber: 2,
					CreatedAt:      timestamptz(time.Now()),
				},
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:         "handles empty result",
			limit:        10,
			offset:       0,
			mockMessages: []sqlc.SessionMessage{},
			wantCount:    0,
			wantErr:      false,
		},
		{
			name:    "returns error on database failure",
			limit:   10,
			offset:  0,
			mockErr: errors.New("database error"),
			wantErr: true,
		},
		{
			name:   "skips malformed messages",
			limit:  10,
			offset: 0,
			mockMessages: []sqlc.SessionMessage{
				{
					ID:             uuidToPgUUID(uuid.New()),
					SessionID:      uuidToPgUUID(sessionID),
					Role:           "user",
					Content:        []byte("invalid json"),
					SequenceNumber: 1,
					CreatedAt:      timestamptz(time.Now()),
				},
				{
					ID:             uuidToPgUUID(uuid.New()),
					SessionID:      uuidToPgUUID(sessionID),
					Role:           "model",
					Content:        contentJSON,
					SequenceNumber: 2,
					CreatedAt:      timestamptz(time.Now()),
				},
			},
			wantCount: 1, // Only second message is valid
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				getMessagesResult: tt.mockMessages,
				getMessagesErr:    tt.mockErr,
			}
			store := New(querier, nil, slog.Default())

			messages, err := store.GetMessages(context.Background(), sessionID, tt.limit, tt.offset)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetMessages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(messages) != tt.wantCount {
				t.Errorf("GetMessages() returned %d messages, want %d", len(messages), tt.wantCount)
			}

			// Verify parameters passed to querier
			if querier.lastGetMessagesParams.ResultLimit != tt.limit {
				t.Errorf("GetMessages() limit = %d, want %d", querier.lastGetMessagesParams.ResultLimit, tt.limit)
			}
			if querier.lastGetMessagesParams.ResultOffset != tt.offset {
				t.Errorf("GetMessages() offset = %d, want %d", querier.lastGetMessagesParams.ResultOffset, tt.offset)
			}
		})
	}
}

func TestStore_DeleteSession(t *testing.T) {
	sessionID := uuid.New()

	tests := []struct {
		name    string
		mockErr error
		wantErr bool
	}{
		{
			name:    "successful deletion",
			wantErr: false,
		},
		{
			name:    "database error",
			mockErr: errors.New("foreign key constraint"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				deleteSessionErr: tt.mockErr,
			}
			store := New(querier, nil, slog.Default())

			err := store.DeleteSession(context.Background(), sessionID)

			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteSession() error = %v, wantErr %v", err, tt.wantErr)
			}

			if querier.deleteSessionCalls != 1 {
				t.Errorf("DeleteSession() calls = %d, want 1", querier.deleteSessionCalls)
			}
		})
	}
}

func TestStore_GetSession(t *testing.T) {
	sessionID := uuid.New()
	now := time.Now()

	tests := []struct {
		name           string
		sessionID      uuid.UUID
		mockResult     sqlc.Session
		mockErr        error
		wantErr        bool
		validateResult func(*testing.T, *Session)
	}{
		{
			name:      "successfully retrieves session",
			sessionID: sessionID,
			mockResult: sqlc.Session{
				ID:           uuidToPgUUID(sessionID),
				Title:        strPtr("Test Session"),
				ModelName:    strPtr("gemini-2.5-pro"),
				SystemPrompt: strPtr("You are a helpful assistant"),
				CreatedAt:    timestamptz(now),
				UpdatedAt:    timestamptz(now),
				MessageCount: int32Ptr(5),
			},
			wantErr: false,
			validateResult: func(t *testing.T, s *Session) {
				t.Helper()
				if s.ID != sessionID {
					t.Errorf("expected ID %s, got %s", sessionID, s.ID)
				}
				if s.Title != "Test Session" {
					t.Errorf("expected title 'Test Session', got '%s'", s.Title)
				}
				if s.ModelName != "gemini-2.5-pro" {
					t.Errorf("expected model 'gemini-2.5-pro', got '%s'", s.ModelName)
				}
				if s.SystemPrompt != "You are a helpful assistant" {
					t.Errorf("expected system prompt, got '%s'", s.SystemPrompt)
				}
				if s.MessageCount != 5 {
					t.Errorf("expected message count 5, got %d", s.MessageCount)
				}
			},
		},
		{
			name:      "session not found",
			sessionID: sessionID,
			mockErr:   errors.New("session not found"),
			wantErr:   true,
		},
		{
			name:      "database error",
			sessionID: sessionID,
			mockErr:   errors.New("database connection failed"),
			wantErr:   true,
		},
		{
			name:      "session with minimal fields",
			sessionID: sessionID,
			mockResult: sqlc.Session{
				ID:           uuidToPgUUID(sessionID),
				CreatedAt:    timestamptz(now),
				UpdatedAt:    timestamptz(now),
				MessageCount: int32Ptr(0),
			},
			wantErr: false,
			validateResult: func(t *testing.T, s *Session) {
				t.Helper()
				if s.ID != sessionID {
					t.Errorf("expected ID %s, got %s", sessionID, s.ID)
				}
				if s.Title != "" {
					t.Errorf("expected empty title, got '%s'", s.Title)
				}
				if s.MessageCount != 0 {
					t.Errorf("expected message count 0, got %d", s.MessageCount)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				getSessionResult: tt.mockResult,
				getSessionErr:    tt.mockErr,
			}
			store := New(querier, nil, slog.Default())

			result, err := store.GetSession(context.Background(), tt.sessionID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if querier.getSessionCalls != 1 {
				t.Errorf("GetSession() calls = %d, want 1", querier.getSessionCalls)
			}

			if !tt.wantErr && tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestStore_ListSessions(t *testing.T) {
	now := time.Now()
	session1ID := uuid.New()
	session2ID := uuid.New()

	tests := []struct {
		name           string
		limit          int32
		offset         int32
		mockResult     []sqlc.Session
		mockErr        error
		wantErr        bool
		expectedCount  int
		validateResult func(*testing.T, []*Session)
	}{
		{
			name:   "successfully lists multiple sessions",
			limit:  10,
			offset: 0,
			mockResult: []sqlc.Session{
				{
					ID:           uuidToPgUUID(session1ID),
					Title:        strPtr("Session 1"),
					ModelName:    strPtr("gemini-2.5-pro"),
					CreatedAt:    timestamptz(now),
					UpdatedAt:    timestamptz(now),
					MessageCount: int32Ptr(5),
				},
				{
					ID:           uuidToPgUUID(session2ID),
					Title:        strPtr("Session 2"),
					ModelName:    strPtr("gemini-2.5-flash"),
					CreatedAt:    timestamptz(now.Add(-time.Hour)),
					UpdatedAt:    timestamptz(now.Add(-time.Hour)),
					MessageCount: int32Ptr(3),
				},
			},
			wantErr:       false,
			expectedCount: 2,
			validateResult: func(t *testing.T, sessions []*Session) {
				t.Helper()
				if len(sessions) != 2 {
					t.Fatalf("expected 2 sessions, got %d", len(sessions))
				}
				if sessions[0].ID != session1ID {
					t.Errorf("expected first session ID %s, got %s", session1ID, sessions[0].ID)
				}
				if sessions[0].Title != "Session 1" {
					t.Errorf("expected first session title 'Session 1', got '%s'", sessions[0].Title)
				}
				if sessions[1].ID != session2ID {
					t.Errorf("expected second session ID %s, got %s", session2ID, sessions[1].ID)
				}
				if sessions[1].MessageCount != 3 {
					t.Errorf("expected second session message count 3, got %d", sessions[1].MessageCount)
				}
			},
		},
		{
			name:          "returns empty list when no sessions",
			limit:         10,
			offset:        0,
			mockResult:    []sqlc.Session{},
			wantErr:       false,
			expectedCount: 0,
			validateResult: func(t *testing.T, sessions []*Session) {
				t.Helper()
				if len(sessions) != 0 {
					t.Errorf("expected empty list, got %d sessions", len(sessions))
				}
			},
		},
		{
			name:    "database error",
			limit:   10,
			offset:  0,
			mockErr: errors.New("database connection failed"),
			wantErr: true,
		},
		{
			name:   "pagination with limit and offset",
			limit:  5,
			offset: 10,
			mockResult: []sqlc.Session{
				{
					ID:           uuidToPgUUID(session1ID),
					Title:        strPtr("Session Page 2"),
					CreatedAt:    timestamptz(now),
					UpdatedAt:    timestamptz(now),
					MessageCount: int32Ptr(0),
				},
			},
			wantErr:       false,
			expectedCount: 1,
			validateResult: func(t *testing.T, sessions []*Session) {
				t.Helper()
				if len(sessions) != 1 {
					t.Fatalf("expected 1 session, got %d", len(sessions))
				}
				if sessions[0].Title != "Session Page 2" {
					t.Errorf("expected title 'Session Page 2', got '%s'", sessions[0].Title)
				}
			},
		},
		{
			name:   "sessions with nil optional fields",
			limit:  10,
			offset: 0,
			mockResult: []sqlc.Session{
				{
					ID:           uuidToPgUUID(session1ID),
					Title:        nil,
					ModelName:    nil,
					SystemPrompt: nil,
					CreatedAt:    timestamptz(now),
					UpdatedAt:    timestamptz(now),
					MessageCount: int32Ptr(0),
				},
			},
			wantErr:       false,
			expectedCount: 1,
			validateResult: func(t *testing.T, sessions []*Session) {
				t.Helper()
				if len(sessions) != 1 {
					t.Fatalf("expected 1 session, got %d", len(sessions))
				}
				if sessions[0].Title != "" {
					t.Errorf("expected empty title, got '%s'", sessions[0].Title)
				}
				if sessions[0].ModelName != "" {
					t.Errorf("expected empty model name, got '%s'", sessions[0].ModelName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				listSessionsResult: tt.mockResult,
				listSessionsErr:    tt.mockErr,
			}
			store := New(querier, nil, slog.Default())

			result, err := store.ListSessions(context.Background(), tt.limit, tt.offset)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListSessions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if querier.listSessionsCalls != 1 {
				t.Errorf("ListSessions() calls = %d, want 1", querier.listSessionsCalls)
			}

			// Verify parameters were passed correctly
			if !tt.wantErr {
				if querier.lastListParams.ResultLimit != tt.limit {
					t.Errorf("expected limit %d, got %d", tt.limit, querier.lastListParams.ResultLimit)
				}
				if querier.lastListParams.ResultOffset != tt.offset {
					t.Errorf("expected offset %d, got %d", tt.offset, querier.lastListParams.ResultOffset)
				}

				if len(result) != tt.expectedCount {
					t.Errorf("expected %d sessions, got %d", tt.expectedCount, len(result))
				}

				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func strPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  t,
		Valid: true,
	}
}
