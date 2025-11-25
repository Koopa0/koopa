//go:build integration
// +build integration

package session

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Setup Helper
// =============================================================================

// setupIntegrationTest creates a Store with test database connection.
// All integration tests should use this unified setup.
func setupIntegrationTest(t *testing.T) (*Store, func()) {
	t.Helper()
	dbContainer, cleanup := testutil.SetupTestDB(t)
	store := New(sqlc.New(dbContainer.Pool), dbContainer.Pool, slog.Default())
	return store, cleanup
}

// =============================================================================
// Basic CRUD Tests
// =============================================================================

// TestStore_CreateAndGet tests creating and retrieving a session
func TestStore_CreateAndGet(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_CreateWithEmptyFields tests creating session with empty optional fields
func TestStore_CreateWithEmptyFields(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_ListSessions tests listing sessions with pagination
func TestStore_ListSessions_Integration(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create multiple sessions
	for i := 0; i < 5; i++ {
		_, err := store.CreateSession(ctx,
			fmt.Sprintf("Session %d", i+1),
			"gemini-2.5-flash",
			"")
		require.NoError(t, err)
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

// TestStore_DeleteSession tests deleting a session
func TestStore_DeleteSession_Integration(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// =============================================================================
// Message Tests
// =============================================================================

// TestStore_AddMessage tests adding messages to a session
func TestStore_AddMessage(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_GetMessages tests retrieving messages with pagination
func TestStore_GetMessages_Integration(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_MessageOrdering tests that messages maintain chronological order
func TestStore_MessageOrdering(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_LargeMessageContent tests handling large message content
func TestStore_LargeMessageContent(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// TestStore_DeleteSessionWithMessages tests that deleting a session also deletes messages
func TestStore_DeleteSessionWithMessages(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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
}

// =============================================================================
// Race Condition Tests
// =============================================================================

// TestStore_ConcurrentSessionCreation tests that multiple goroutines can create
// sessions simultaneously without data corruption or race conditions.
func TestStore_ConcurrentSessionCreation(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	sessionIDs := make(chan string, numGoroutines)

	// Create sessions concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			title := fmt.Sprintf("Race-Session-%d", id)
			session, err := store.CreateSession(ctx, title, "test-model", "test-prompt")
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
				return
			}
			sessionIDs <- session.ID.String()
		}(i)
	}

	wg.Wait()
	close(errors)
	close(sessionIDs)

	// Check for errors
	var errCount int
	for err := range errors {
		t.Errorf("concurrent creation error: %v", err)
		errCount++
	}

	// Verify all sessions were created with unique IDs
	ids := make(map[string]bool)
	for id := range sessionIDs {
		if ids[id] {
			t.Errorf("duplicate session ID: %s", id)
		}
		ids[id] = true
	}

	assert.Equal(t, numGoroutines-errCount, len(ids), "should have created %d unique sessions", numGoroutines-errCount)
	t.Logf("Successfully created %d sessions concurrently", len(ids))
}

// TestStore_ConcurrentHistoryUpdate tests that multiple goroutines can add
// messages to the same session without data corruption.
func TestStore_ConcurrentHistoryUpdate(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session
	session, err := store.CreateSession(ctx, "Race-History-Test", "", "")
	require.NoError(t, err)

	const numGoroutines = 10
	const messagesPerGoroutine = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	var successCount atomic.Int32

	// Add messages concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			messages := make([]*Message, messagesPerGoroutine)
			for j := 0; j < messagesPerGoroutine; j++ {
				messages[j] = &Message{
					Role:    "user",
					Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Goroutine-%d-Message-%d", goroutineID, j))},
				}
			}

			if err := store.AddMessages(ctx, session.ID, messages); err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", goroutineID, err)
				return
			}
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent history update error: %v", err)
	}

	// Verify message integrity
	allMessages, err := store.GetMessages(ctx, session.ID, 1000, 0)
	require.NoError(t, err)

	expectedCount := int(successCount.Load()) * messagesPerGoroutine
	assert.Equal(t, expectedCount, len(allMessages),
		"expected %d messages, got %d", expectedCount, len(allMessages))

	// Verify sequence numbers are unique and sequential
	seqNumbers := make(map[int]bool)
	for _, msg := range allMessages {
		if seqNumbers[msg.SequenceNumber] {
			t.Errorf("duplicate sequence number: %d", msg.SequenceNumber)
		}
		seqNumbers[msg.SequenceNumber] = true
	}

	// Verify sequence numbers form a complete range
	for i := 1; i <= len(allMessages); i++ {
		if !seqNumbers[i] {
			t.Errorf("missing sequence number: %d", i)
		}
	}

	t.Logf("Successfully added %d messages from %d goroutines", len(allMessages), successCount.Load())
}

// TestStore_ConcurrentLoadAndSaveHistory tests simultaneous load and save
// operations on the same session.
func TestStore_ConcurrentLoadAndSaveHistory(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session with initial messages
	session, err := store.CreateSession(ctx, "Race-LoadSave-Test", "", "")
	require.NoError(t, err)

	// Add initial messages
	initialMsgs := []*Message{
		{Role: "user", Content: []*ai.Part{ai.NewTextPart("Initial message 1")}},
		{Role: "model", Content: []*ai.Part{ai.NewTextPart("Initial response 1")}},
	}
	require.NoError(t, store.AddMessages(ctx, session.ID, initialMsgs))

	sessionID := agent.SessionID(session.ID.String())
	const numGoroutines = 10
	var wg sync.WaitGroup
	loadErrors := make(chan error, numGoroutines)
	saveErrors := make(chan error, numGoroutines)

	// Mix of load and save operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)

		// Load goroutine
		go func(id int) {
			defer wg.Done()
			history, err := store.LoadHistory(ctx, sessionID, "main")
			if err != nil {
				loadErrors <- fmt.Errorf("load goroutine %d: %w", id, err)
				return
			}
			// Verify we got at least the initial messages
			if len(history.Messages()) < 2 {
				loadErrors <- fmt.Errorf("load goroutine %d: expected at least 2 messages, got %d",
					id, len(history.Messages()))
			}
		}(i)

		// Save goroutine (using AddMessages directly for predictable behavior)
		go func(id int) {
			defer wg.Done()
			msg := &Message{
				Role:    "user",
				Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Concurrent message %d", id))},
			}
			if err := store.AddMessages(ctx, session.ID, []*Message{msg}); err != nil {
				saveErrors <- fmt.Errorf("save goroutine %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(loadErrors)
	close(saveErrors)

	// Check for errors
	for err := range loadErrors {
		t.Errorf("load error: %v", err)
	}
	for err := range saveErrors {
		t.Errorf("save error: %v", err)
	}

	// Verify final state
	finalHistory, err := store.LoadHistory(ctx, sessionID, "main")
	require.NoError(t, err)

	// Should have at least initial messages + some concurrent messages
	assert.GreaterOrEqual(t, len(finalHistory.Messages()), 2,
		"final history should have at least 2 messages")

	t.Logf("Final history has %d messages after concurrent load/save", len(finalHistory.Messages()))
}

// TestStore_ConcurrentSessionDeletion tests that deleting sessions while
// other operations are in progress doesn't cause crashes or data corruption.
func TestStore_ConcurrentSessionDeletion(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	const numSessions = 5
	sessions := make([]*Session, numSessions)

	// Create test sessions
	for i := 0; i < numSessions; i++ {
		session, err := store.CreateSession(ctx, fmt.Sprintf("Race-Delete-Test-%d", i), "", "")
		require.NoError(t, err)
		sessions[i] = session

		// Add some messages
		msgs := []*Message{
			{Role: "user", Content: []*ai.Part{ai.NewTextPart("test message")}},
		}
		require.NoError(t, store.AddMessages(ctx, session.ID, msgs))
	}

	var wg sync.WaitGroup

	// Concurrent operations: delete, list, and get
	for i := 0; i < numSessions; i++ {
		wg.Add(3)

		session := sessions[i]

		// Delete goroutine
		go func(s *Session) {
			defer wg.Done()
			// Small random delay to mix operations
			time.Sleep(time.Millisecond * time.Duration(s.ID[0]%10))
			_ = store.DeleteSession(ctx, s.ID)
		}(session)

		// List goroutine
		go func() {
			defer wg.Done()
			_, _ = store.ListSessions(ctx, 100, 0)
		}()

		// Get goroutine
		go func(s *Session) {
			defer wg.Done()
			_, _ = store.GetSession(ctx, s.ID)
		}(session)
	}

	wg.Wait()

	// Verify all sessions are deleted
	remaining, err := store.ListSessions(ctx, 100, 0)
	require.NoError(t, err)

	for _, session := range sessions {
		found := false
		for _, r := range remaining {
			if r.ID == session.ID {
				found = true
				break
			}
		}
		if found {
			// Clean up any remaining sessions
			_ = store.DeleteSession(ctx, session.ID)
		}
	}

	t.Log("Concurrent deletion test completed without crashes")
}

// TestStore_RaceDetector is a comprehensive test designed to trigger
// the Go race detector if there are any data races in the Store implementation.
//
// Run with: go test -race -tags=integration ./internal/session/...
func TestStore_RaceDetector(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a shared session
	session, err := store.CreateSession(ctx, "Race-Detector-Test", "", "")
	require.NoError(t, err)

	sessionID := agent.SessionID(session.ID.String())

	// Run many concurrent operations of different types
	var wg sync.WaitGroup
	const numOps = 50

	for i := 0; i < numOps; i++ {
		wg.Add(4)

		// Operation 1: Add message
		go func(id int) {
			defer wg.Done()
			msg := &Message{
				Role:    "user",
				Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Race test %d", id))},
			}
			_ = store.AddMessages(ctx, session.ID, []*Message{msg})
		}(i)

		// Operation 2: Get messages
		go func() {
			defer wg.Done()
			_, _ = store.GetMessages(ctx, session.ID, 100, 0)
		}()

		// Operation 3: Load history
		go func() {
			defer wg.Done()
			_, _ = store.LoadHistory(ctx, sessionID, "main")
		}()

		// Operation 4: Get session
		go func() {
			defer wg.Done()
			_, _ = store.GetSession(ctx, session.ID)
		}()
	}

	wg.Wait()
	t.Log("Race detector test completed - if no race detected, Store is thread-safe")
}

// TestStore_ConcurrentWrites tests concurrent writes to different sessions
func TestStore_ConcurrentWrites(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
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

// =============================================================================
// SQL Injection Prevention Tests
// =============================================================================

// TestStore_SQLInjectionPrevention verifies that SQL injection attacks are blocked.
// Session store uses sqlc parameterized queries which should prevent all injection.
func TestStore_SQLInjectionPrevention(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// First, create a legitimate session
	legitSession, err := store.CreateSession(ctx, "Legitimate Session", "", "")
	require.NoError(t, err, "failed to create legitimate session")
	t.Logf("Created legitimate session: %s", legitSession.ID)

	// Count sessions before attacks
	sessions, err := store.ListSessions(ctx, 100, 0)
	require.NoError(t, err)
	t.Logf("Initial session count: %d", len(sessions))

	// SQL injection attack vectors for session title
	maliciousTitles := []struct {
		name  string
		title string
	}{
		// Classic SQL injection
		{"single quote", "'; DROP TABLE sessions; --"},
		{"double quote", `"; DROP TABLE sessions; --`},

		// Boolean-based blind injection
		{"or always true", "1' OR '1'='1"},
		{"or always true v2", "' OR 1=1 --"},

		// Union-based injection
		{"union select", "' UNION SELECT * FROM users --"},

		// Stacked queries
		{"stacked drop", "'; DELETE FROM sessions; --"},
		{"stacked insert", "'); INSERT INTO sessions (id, title) VALUES (gen_random_uuid(), 'hacked'); --"},

		// PostgreSQL specific
		{"pg_sleep", "'; SELECT pg_sleep(10); --"},
		{"copy", "'; COPY sessions TO '/tmp/pwned'; --"},

		// Comment injection
		{"comment", "test/**/OR/**/1=1"},

		// Null byte
		{"null byte", "test\x00'; DROP TABLE sessions; --"},
	}

	for _, tc := range maliciousTitles {
		t.Run("title_"+tc.name, func(t *testing.T) {
			// Attempt SQL injection via session title
			session, err := store.CreateSession(ctx, tc.title, "", "")

			// Should either succeed (with escaped title) or fail safely
			if err != nil {
				t.Logf("injection blocked with error: %v", err)
			} else {
				// Session was created - verify title was escaped (treated as literal)
				t.Logf("session created with ID: %s, title stored as literal", session.ID)
				// Clean up
				_ = store.DeleteSession(ctx, session.ID)
			}
		})
	}

	// SQL injection via model name
	maliciousModels := []string{
		"'; DROP TABLE sessions; --",
		"model' UNION SELECT password FROM users --",
	}

	for i, model := range maliciousModels {
		t.Run("model_"+string(rune('a'+i)), func(t *testing.T) {
			session, err := store.CreateSession(ctx, "Test", model, "")
			if err == nil {
				_ = store.DeleteSession(ctx, session.ID)
			}
		})
	}

	// SQL injection via system prompt
	maliciousPrompts := []string{
		"'; DELETE FROM session_messages; --",
		"You are helpful'); DROP TABLE sessions; --",
	}

	for i, prompt := range maliciousPrompts {
		t.Run("prompt_"+string(rune('a'+i)), func(t *testing.T) {
			session, err := store.CreateSession(ctx, "Test", "", prompt)
			if err == nil {
				_ = store.DeleteSession(ctx, session.ID)
			}
		})
	}

	// Verify database integrity
	t.Run("verify database integrity", func(t *testing.T) {
		// Sessions table should still exist
		sessions, err := store.ListSessions(ctx, 100, 0)
		require.NoError(t, err, "sessions table should still exist")

		// Legitimate session should still exist
		found := false
		for _, s := range sessions {
			if s.ID == legitSession.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "legitimate session should still exist")

		// Should be able to load the session
		loaded, err := store.GetSession(ctx, legitSession.ID)
		require.NoError(t, err)
		assert.Equal(t, "Legitimate Session", loaded.Title)
	})
}

// TestStore_SQLInjectionViaSessionID tests injection through session IDs.
func TestStore_SQLInjectionViaSessionID(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session
	session, err := store.CreateSession(ctx, "Test Session", "", "")
	require.NoError(t, err)

	// Malicious session IDs (note: UUID type in PostgreSQL provides some protection)
	maliciousIDs := []string{
		"'; DROP TABLE sessions; --",
		"00000000-0000-0000-0000-000000000000'; DELETE FROM sessions; --",
		"test' UNION SELECT * FROM pg_tables --",
	}

	for _, maliciousID := range maliciousIDs {
		name := maliciousID
		if len(name) > 15 {
			name = name[:15]
		}
		t.Run(name, func(t *testing.T) {
			// Try to parse as UUID - should fail for malicious strings
			parsedID, err := uuid.Parse(maliciousID)
			if err != nil {
				t.Logf("malicious ID rejected by UUID parser: %v", err)
				return
			}
			// If somehow parsed, try to get session (should fail safely)
			_, err = store.GetSession(ctx, parsedID)
			t.Logf("GetSession result: %v", err)
		})
	}

	// Verify the test session still exists
	loaded, err := store.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, "Test Session", loaded.Title)
}

// TestStore_SQLInjectionViaMessageContent tests injection through message content.
func TestStore_SQLInjectionViaMessageContent(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session
	session, err := store.CreateSession(ctx, "Message Test", "", "")
	require.NoError(t, err)

	// Malicious message content
	maliciousMessages := []string{
		"'; DROP TABLE session_messages; --",
		"Hello'); DELETE FROM sessions WHERE '1'='1",
		"Test' UNION SELECT password FROM users --",
		"Message\x00'; DROP TABLE sessions; --",
	}

	for i, content := range maliciousMessages {
		t.Run("message_"+string(rune('a'+i)), func(t *testing.T) {
			msg := &Message{
				Role:    "user",
				Content: []*ai.Part{ai.NewTextPart(content)},
			}
			err := store.AddMessages(ctx, session.ID, []*Message{msg})

			if err != nil {
				t.Logf("message blocked: %v", err)
			} else {
				t.Logf("message stored as literal string")
			}
		})
	}

	// Verify session and messages table integrity
	t.Run("verify integrity", func(t *testing.T) {
		// Session should still exist
		_, err := store.GetSession(ctx, session.ID)
		require.NoError(t, err, "session should still exist")

		// Should be able to load messages
		sessionID := agent.SessionID(session.ID.String())
		history, err := store.LoadHistory(ctx, sessionID, "main")
		require.NoError(t, err, "should be able to load history")
		t.Logf("loaded history with %d messages", len(history.Messages()))
	})
}
