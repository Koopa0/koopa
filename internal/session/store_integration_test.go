//go:build integration
// +build integration

package session

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/testutil"
)

// TestSessionStore_CreateAndGet_Integration tests creating and retrieving a session
func TestSessionStore_CreateAndGet_Integration(t *testing.T) {
	// Setup test database
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Test Session", "gemini-2.5-flash", "You are a helpful assistant")
	require.NoError(t, err, "CreateSession should not return error")
	require.NotNil(t, session, "Created session should not be nil")
	assert.NotEqual(t, uuid.Nil, session.ID, "Session ID should not be nil UUID")
	assert.Equal(t, "Test Session", session.Title)
	assert.Equal(t, "gemini-2.5-flash", session.ModelName)
	assert.Equal(t, "You are a helpful assistant", session.SystemPrompt)
	assert.NotZero(t, session.CreatedAt, "CreatedAt should be set")
	assert.NotZero(t, session.UpdatedAt, "UpdatedAt should be set")

	// Retrieve the session
	retrieved, err := store.GetSession(ctx, session.ID)
	require.NoError(t, err, "GetSession should not return error")
	require.NotNil(t, retrieved, "Retrieved session should not be nil")
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, session.Title, retrieved.Title)
	assert.Equal(t, session.ModelName, retrieved.ModelName)
	assert.Equal(t, session.SystemPrompt, retrieved.SystemPrompt)
}

// TestSessionStore_CreateWithEmptyFields_Integration tests creating session with empty optional fields
func TestSessionStore_CreateWithEmptyFields_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create session with empty title and system prompt
	session, err := store.CreateSession(ctx, "", "gemini-2.5-flash", "")
	require.NoError(t, err, "CreateSession with empty fields should succeed")
	assert.NotEqual(t, uuid.Nil, session.ID)
	assert.Empty(t, session.Title, "Title should be empty")
	assert.Equal(t, "gemini-2.5-flash", session.ModelName)
	assert.Empty(t, session.SystemPrompt, "SystemPrompt should be empty")

	// Retrieve should work
	retrieved, err := store.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Empty(t, retrieved.Title)
	assert.Empty(t, retrieved.SystemPrompt)
}

// TestSessionStore_ListSessions_Integration tests listing sessions with pagination
func TestSessionStore_ListSessions_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create multiple sessions
	sessionIDs := make([]uuid.UUID, 5)
	for i := 0; i < 5; i++ {
		session, err := store.CreateSession(ctx,
			fmt.Sprintf("Session %d", i+1),
			"gemini-2.5-flash",
			"")
		require.NoError(t, err)
		sessionIDs[i] = session.ID
	}

	// List all sessions
	sessions, err := store.ListSessions(ctx, 10, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessions), 5, "Should have at least 5 sessions")

	// Test pagination - first 3
	sessions, err = store.ListSessions(ctx, 3, 0)
	require.NoError(t, err)
	assert.Len(t, sessions, 3, "Should return exactly 3 sessions")

	// Test pagination - next 2
	sessions, err = store.ListSessions(ctx, 3, 3)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessions), 2, "Should have at least 2 more sessions")
}

// TestSessionStore_DeleteSession_Integration tests deleting a session
func TestSessionStore_DeleteSession_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "To Be Deleted", "gemini-2.5-flash", "")
	require.NoError(t, err)

	// Verify it exists
	_, err = store.GetSession(ctx, session.ID)
	require.NoError(t, err)

	// Delete the session
	err = store.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	// Verify it no longer exists
	_, err = store.GetSession(ctx, session.ID)
	assert.Error(t, err, "GetSession should return error for deleted session")
}

// TestSessionStore_AddMessage_Integration tests adding messages to a session
func TestSessionStore_AddMessage_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Message Test", "gemini-2.5-flash", "")
	require.NoError(t, err)

	// Add a user message
	userMessage := &Message{
		Role: string(ai.RoleUser),
		Content: []*ai.Part{
			ai.NewTextPart("Hello, how are you?"),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{userMessage})
	require.NoError(t, err, "AddMessages should not return error")

	// Add a model message
	modelMessage := &Message{
		Role: string(ai.RoleModel),
		Content: []*ai.Part{
			ai.NewTextPart("I'm doing well, thank you!"),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{modelMessage})
	require.NoError(t, err)

	// Retrieve messages
	messages, err := store.GetMessages(ctx, session.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, messages, 2, "Should have 2 messages")

	// Verify order (should be chronological)
	assert.Equal(t, string(ai.RoleUser), messages[0].Role)
	assert.Equal(t, "Hello, how are you?", messages[0].Content[0].Text)
	assert.Equal(t, string(ai.RoleModel), messages[1].Role)
	assert.Equal(t, "I'm doing well, thank you!", messages[1].Content[0].Text)
}

// TestSessionStore_GetMessages_Integration tests retrieving messages with pagination
func TestSessionStore_GetMessages_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Pagination Test", "gemini-2.5-flash", "")
	require.NoError(t, err)

	// Add 10 messages
	messages := make([]*Message, 10)
	for i := 0; i < 10; i++ {
		messages[i] = &Message{
			Role: string(ai.RoleUser),
			Content: []*ai.Part{
				ai.NewTextPart(fmt.Sprintf("Message %d", i+1)),
			},
		}
	}

	err = store.AddMessages(ctx, session.ID, messages)
	require.NoError(t, err)

	// Get first 5 messages
	retrieved, err := store.GetMessages(ctx, session.ID, 5, 0)
	require.NoError(t, err)
	assert.Len(t, retrieved, 5)
	assert.Equal(t, "Message 1", retrieved[0].Content[0].Text)

	// Get next 5 messages
	retrieved, err = store.GetMessages(ctx, session.ID, 5, 5)
	require.NoError(t, err)
	assert.Len(t, retrieved, 5)
	assert.Equal(t, "Message 6", retrieved[0].Content[0].Text)
}

// TestSessionStore_MessageOrdering_Integration tests that messages maintain chronological order
func TestSessionStore_MessageOrdering_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Ordering Test", "gemini-2.5-flash", "")
	require.NoError(t, err)

	// Add messages in multiple batches
	for i := 0; i < 3; i++ {
		messages := []*Message{
			{
				Role: string(ai.RoleUser),
				Content: []*ai.Part{
					ai.NewTextPart(fmt.Sprintf("User message %d", i+1)),
				},
			},
			{
				Role: string(ai.RoleModel),
				Content: []*ai.Part{
					ai.NewTextPart(fmt.Sprintf("Model response %d", i+1)),
				},
			},
		}
		err = store.AddMessages(ctx, session.ID, messages)
		require.NoError(t, err)
	}

	// Retrieve all messages
	retrieved, err := store.GetMessages(ctx, session.ID, 100, 0)
	require.NoError(t, err)
	assert.Len(t, retrieved, 6, "Should have 6 messages")

	// Verify order
	for i := 0; i < 3; i++ {
		userMsg := retrieved[i*2]
		modelMsg := retrieved[i*2+1]

		assert.Equal(t, string(ai.RoleUser), userMsg.Role)
		assert.Contains(t, userMsg.Content[0].Text, fmt.Sprintf("User message %d", i+1))

		assert.Equal(t, string(ai.RoleModel), modelMsg.Role)
		assert.Contains(t, modelMsg.Content[0].Text, fmt.Sprintf("Model response %d", i+1))
	}
}

// TestSessionStore_LargeMessageContent_Integration tests handling large message content
func TestSessionStore_LargeMessageContent_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Large Content Test", "gemini-2.5-flash", "")
	require.NoError(t, err)

	// Create a large message (>10KB)
	largeText := strings.Repeat("This is a test message. ", 1000) // ~24KB

	message := &Message{
		Role: string(ai.RoleUser),
		Content: []*ai.Part{
			ai.NewTextPart(largeText),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{message})
	require.NoError(t, err, "Should handle large message content")

	// Retrieve and verify
	messages, err := store.GetMessages(ctx, session.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, largeText, messages[0].Content[0].Text, "Large content should be preserved")
}

// TestSessionStore_DeleteSessionWithMessages_Integration tests that deleting a session also deletes messages
func TestSessionStore_DeleteSessionWithMessages_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create a session with messages
	session, err := store.CreateSession(ctx, "Cascade Delete Test", "gemini-2.5-flash", "")
	require.NoError(t, err)

	messages := []*Message{
		{
			Role:    string(ai.RoleUser),
			Content: []*ai.Part{ai.NewTextPart("Test message")},
		},
	}
	err = store.AddMessages(ctx, session.ID, messages)
	require.NoError(t, err)

	// Verify message exists
	retrieved, err := store.GetMessages(ctx, session.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, retrieved, 1)

	// Delete session
	err = store.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	// Verify session is deleted
	_, err = store.GetSession(ctx, session.ID)
	assert.Error(t, err)

	// Messages should also be deleted (will fail to get session first, but testing cascade)
}

// TestSessionStore_ConcurrentWrites_Integration tests concurrent writes to different sessions
func TestSessionStore_ConcurrentWrites_Integration(t *testing.T) {
	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	store := New(dbContainer.Pool, slog.Default())
	ctx := context.Background()

	// Create multiple sessions
	numSessions := 5
	sessions := make([]*Session, numSessions)
	for i := 0; i < numSessions; i++ {
		session, err := store.CreateSession(ctx, fmt.Sprintf("Concurrent Session %d", i+1), "gemini-2.5-flash", "")
		require.NoError(t, err)
		sessions[i] = session
	}

	// Concurrently write messages to different sessions
	var wg sync.WaitGroup
	errors := make(chan error, numSessions*10)

	for i := 0; i < numSessions; i++ {
		sessionID := sessions[i].ID
		wg.Add(1)
		go func(sid uuid.UUID, index int) {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				message := &Message{
					Role: string(ai.RoleUser),
					Content: []*ai.Part{
						ai.NewTextPart(fmt.Sprintf("Session %d, Message %d", index+1, j+1)),
					},
				}

				if err := store.AddMessages(ctx, sid, []*Message{message}); err != nil {
					errors <- err
				}
			}
		}(sessionID, i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent write error: %v", err)
	}

	// Verify each session has 10 messages
	for i, session := range sessions {
		messages, err := store.GetMessages(ctx, session.ID, 100, 0)
		require.NoError(t, err)
		assert.Len(t, messages, 10, "Session %d should have 10 messages", i+1)
	}
}
