package session

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	addMessageErr             error
	getMessagesErr            error
	getMaxSequenceNumberErr   error

	// Return values
	createSessionResult      sqlc.Session
	getSessionResult         sqlc.Session
	listSessionsResult       []sqlc.Session
	getMessagesResult        []sqlc.SessionMessage
	getMaxSequenceNumberResult interface{}

	// Call tracking
	createSessionCalls       int
	getSessionCalls          int
	listSessionsCalls        int
	updateSessionUpdatedAtCalls int
	deleteSessionCalls       int
	addMessageCalls          int
	getMessagesCalls         int
	getMaxSequenceNumberCalls int

	lastCreateParams         sqlc.CreateSessionParams
	lastGetSessionID         pgtype.UUID
	lastListParams           sqlc.ListSessionsParams
	lastUpdateParams         sqlc.UpdateSessionUpdatedAtParams
	lastDeleteSessionID      pgtype.UUID
	lastAddMessageParams     []sqlc.AddMessageParams
	lastGetMessagesParams    sqlc.GetMessagesParams
	lastMaxSeqSessionID      pgtype.UUID
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

func (m *mockSessionQuerier) GetMaxSequenceNumber(ctx context.Context, sessionID pgtype.UUID) (interface{}, error) {
	m.getMaxSequenceNumberCalls++
	m.lastMaxSeqSessionID = sessionID
	if m.getMaxSequenceNumberErr != nil {
		return nil, m.getMaxSequenceNumberErr
	}
	if m.getMaxSequenceNumberResult == nil {
		return int64(0), nil
	}
	return m.getMaxSequenceNumberResult, nil
}

// ============================================================================
// Tests
// ============================================================================

func TestNewWithQuerier(t *testing.T) {
	t.Run("creates store with custom logger", func(t *testing.T) {
		logger := slog.Default()
		querier := &mockSessionQuerier{}

		store := NewWithQuerier(querier, logger)

		if store == nil {
			t.Fatal("expected non-nil store")
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

		store := NewWithQuerier(querier, nil)

		if store == nil {
			t.Fatal("expected non-nil store")
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
			name:      "successful creation with all fields",
			title:     "Test Session",
			modelName: "gemini-2.5-pro",
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
			name:      "successful creation with empty optional fields",
			title:     "",
			modelName: "",
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
			store := NewWithQuerier(querier, slog.Default())

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

	tests := []struct {
		name                string
		messages            []*Message
		mockMaxSeq          interface{}
		mockMaxSeqErr       error
		mockAddErr          error
		wantAddMessageCalls int
		wantErr             bool
	}{
		{
			name: "successfully adds multiple messages",
			messages: []*Message{
				{
					SessionID: sessionID,
					Role:      "user",
					Content:   testParts,
				},
				{
					SessionID: sessionID,
					Role:      "model",
					Content:   testParts,
				},
			},
			mockMaxSeq:          int64(0),
			wantAddMessageCalls: 2,
			wantErr:             false,
		},
		{
			name:                "handles empty message slice",
			messages:            []*Message{},
			wantAddMessageCalls: 0,
			wantErr:             false,
		},
		{
			name: "continues with sequence 1 when max seq fails",
			messages: []*Message{
				{
					SessionID: sessionID,
					Role:      "user",
					Content:   testParts,
				},
			},
			mockMaxSeqErr:       errors.New("failed to get max seq"),
			wantAddMessageCalls: 1,
			wantErr:             false,
		},
		{
			name: "returns error when add message fails",
			messages: []*Message{
				{
					SessionID: sessionID,
					Role:      "user",
					Content:   testParts,
				},
			},
			mockMaxSeq:          int64(0),
			mockAddErr:          errors.New("insert failed"),
			wantAddMessageCalls: 1,
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier := &mockSessionQuerier{
				getMaxSequenceNumberResult: tt.mockMaxSeq,
				getMaxSequenceNumberErr:    tt.mockMaxSeqErr,
				addMessageErr:              tt.mockAddErr,
			}
			store := NewWithQuerier(querier, slog.Default())

			err := store.AddMessages(context.Background(), sessionID, tt.messages)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddMessages() error = %v, wantErr %v", err, tt.wantErr)
			}

			if querier.addMessageCalls != tt.wantAddMessageCalls {
				t.Errorf("AddMessage() calls = %d, want %d", querier.addMessageCalls, tt.wantAddMessageCalls)
			}

			// Verify sequence numbers are sequential
			if !tt.wantErr && len(tt.messages) > 0 {
				for i, param := range querier.lastAddMessageParams {
					expectedSeq := int32(i + 1)
					if param.SequenceNumber != expectedSeq {
						t.Errorf("message %d: sequence = %d, want %d", i, param.SequenceNumber, expectedSeq)
					}
				}
			}
		})
	}
}

func TestStore_GetMessages(t *testing.T) {
	sessionID := uuid.New()
	testContent := []*ai.Part{ai.NewTextPart("Test message")}
	contentJSON, _ := json.Marshal(testContent)

	tests := []struct {
		name         string
		limit        int
		offset       int
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
			store := NewWithQuerier(querier, slog.Default())

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
			store := NewWithQuerier(querier, slog.Default())

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
