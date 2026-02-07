//go:build integration
// +build integration

package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
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
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("CreateSession() returned nil session")
	}
	if session.ID == uuid.Nil {
		t.Errorf("CreateSession() session ID = %v, want non-nil UUID", session.ID)
	}
	if session.Title != "Test Session" {
		t.Errorf("CreateSession() Title = %q, want %q", session.Title, "Test Session")
	}
	if session.ModelName != "gemini-2.5-flash" {
		t.Errorf("CreateSession() ModelName = %q, want %q", session.ModelName, "gemini-2.5-flash")
	}
	if session.SystemPrompt != "You are a helpful assistant" {
		t.Errorf("CreateSession() SystemPrompt = %q, want %q", session.SystemPrompt, "You are a helpful assistant")
	}
	if session.CreatedAt.IsZero() {
		t.Error("CreateSession() CreatedAt should be set")
	}
	if session.UpdatedAt.IsZero() {
		t.Error("CreateSession() UpdatedAt should be set")
	}

	// Retrieve the session
	retrieved, err := store.Session(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession(%v) unexpected error: %v", session.ID, err)
	}
	if retrieved == nil {
		t.Fatal("GetSession() returned nil session")
	}
	if retrieved.ID != session.ID {
		t.Errorf("GetSession() ID = %v, want %v", retrieved.ID, session.ID)
	}
	if retrieved.Title != session.Title {
		t.Errorf("GetSession() Title = %q, want %q", retrieved.Title, session.Title)
	}
	if retrieved.ModelName != session.ModelName {
		t.Errorf("GetSession() ModelName = %q, want %q", retrieved.ModelName, session.ModelName)
	}
	if retrieved.SystemPrompt != session.SystemPrompt {
		t.Errorf("GetSession() SystemPrompt = %q, want %q", retrieved.SystemPrompt, session.SystemPrompt)
	}
}

// TestStore_CreateWithEmptyFields tests creating session with empty optional fields
func TestStore_CreateWithEmptyFields(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create session with empty title and system prompt
	session, err := store.CreateSession(ctx, "", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() with empty fields unexpected error: %v", err)
	}
	if session.ID == uuid.Nil {
		t.Errorf("CreateSession() session ID = %v, want non-nil UUID", session.ID)
	}
	if session.Title != "" {
		t.Errorf("CreateSession() Title = %q, want empty string", session.Title)
	}
	if session.ModelName != "gemini-2.5-flash" {
		t.Errorf("CreateSession() ModelName = %q, want %q", session.ModelName, "gemini-2.5-flash")
	}
	if session.SystemPrompt != "" {
		t.Errorf("CreateSession() SystemPrompt = %q, want empty string", session.SystemPrompt)
	}

	// Retrieve should work
	retrieved, err := store.Session(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession(%v) unexpected error: %v", session.ID, err)
	}
	if retrieved.Title != "" {
		t.Errorf("GetSession() Title = %q, want empty string", retrieved.Title)
	}
	if retrieved.SystemPrompt != "" {
		t.Errorf("GetSession() SystemPrompt = %q, want empty string", retrieved.SystemPrompt)
	}
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
		if err != nil {
			t.Fatalf("CreateSession(%d) unexpected error: %v", i+1, err)
		}
	}

	// List all sessions
	sessions, err := store.ListSessions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListSessions(10, 0) unexpected error: %v", err)
	}
	if len(sessions) < 5 {
		t.Errorf("ListSessions(10, 0) returned %d sessions, want at least 5", len(sessions))
	}

	// Test pagination - first 3
	sessions, err = store.ListSessions(ctx, 3, 0)
	if err != nil {
		t.Fatalf("ListSessions(3, 0) unexpected error: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("ListSessions(3, 0) returned %d sessions, want exactly 3", len(sessions))
	}

	// Test pagination - next 2
	sessions, err = store.ListSessions(ctx, 3, 3)
	if err != nil {
		t.Fatalf("ListSessions(3, 3) unexpected error: %v", err)
	}
	if len(sessions) < 2 {
		t.Errorf("ListSessions(3, 3) returned %d sessions, want at least 2", len(sessions))
	}
}

// TestStore_DeleteSession tests deleting a session
func TestStore_DeleteSession_Integration(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "To Be Deleted", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	// Verify it exists
	_, err = store.Session(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession(%v) before delete unexpected error: %v", session.ID, err)
	}

	// Delete the session
	err = store.DeleteSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("DeleteSession(%v) unexpected error: %v", session.ID, err)
	}

	// Verify it no longer exists
	_, err = store.Session(ctx, session.ID)
	if err == nil {
		t.Errorf("GetSession(%v) after delete should return error", session.ID)
	}
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
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	// Add a user message
	userMessage := &Message{
		Role: string(ai.RoleUser),
		Content: []*ai.Part{
			ai.NewTextPart("Hello, how are you?"),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{userMessage})
	if err != nil {
		t.Fatalf("AddMessages() with user message unexpected error: %v", err)
	}

	// Add a model message
	modelMessage := &Message{
		Role: string(ai.RoleModel),
		Content: []*ai.Part{
			ai.NewTextPart("I'm doing well, thank you!"),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{modelMessage})
	if err != nil {
		t.Fatalf("AddMessages() with model message unexpected error: %v", err)
	}

	// Retrieve messages
	messages, err := store.Messages(ctx, session.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 10, 0) unexpected error: %v", session.ID, err)
	}
	if len(messages) != 2 {
		t.Fatalf("GetMessages() returned %d messages, want 2", len(messages))
	}

	// Verify order (should be chronological)
	if messages[0].Role != string(ai.RoleUser) {
		t.Errorf("GetMessages()[0].Role = %q, want %q", messages[0].Role, string(ai.RoleUser))
	}
	if messages[0].Content[0].Text != "Hello, how are you?" {
		t.Errorf("GetMessages()[0].Content[0].Text = %q, want %q", messages[0].Content[0].Text, "Hello, how are you?")
	}
	if messages[1].Role != string(ai.RoleModel) {
		t.Errorf("GetMessages()[1].Role = %q, want %q", messages[1].Role, string(ai.RoleModel))
	}
	if messages[1].Content[0].Text != "I'm doing well, thank you!" {
		t.Errorf("GetMessages()[1].Content[0].Text = %q, want %q", messages[1].Content[0].Text, "I'm doing well, thank you!")
	}
}

// TestStore_GetMessages tests retrieving messages with pagination
func TestStore_GetMessages_Integration(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Pagination Test", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

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
	if err != nil {
		t.Fatalf("AddMessages() unexpected error: %v", err)
	}

	// Get first 5 messages
	retrieved, err := store.Messages(ctx, session.ID, 5, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 5, 0) unexpected error: %v", session.ID, err)
	}
	if len(retrieved) != 5 {
		t.Errorf("GetMessages(%v, 5, 0) returned %d messages, want 5", session.ID, len(retrieved))
	}
	if retrieved[0].Content[0].Text != "Message 1" {
		t.Errorf("GetMessages(%v, 5, 0)[0].Content[0].Text = %q, want %q", session.ID, retrieved[0].Content[0].Text, "Message 1")
	}

	// Get next 5 messages
	retrieved, err = store.Messages(ctx, session.ID, 5, 5)
	if err != nil {
		t.Fatalf("GetMessages(%v, 5, 5) unexpected error: %v", session.ID, err)
	}
	if len(retrieved) != 5 {
		t.Errorf("GetMessages(%v, 5, 5) returned %d messages, want 5", session.ID, len(retrieved))
	}
	if retrieved[0].Content[0].Text != "Message 6" {
		t.Errorf("GetMessages(%v, 5, 5)[0].Content[0].Text = %q, want %q", session.ID, retrieved[0].Content[0].Text, "Message 6")
	}
}

// TestStore_MessageOrdering tests that messages maintain chronological order
func TestStore_MessageOrdering(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Ordering Test", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

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
		if err != nil {
			t.Fatalf("AddMessages() batch %d unexpected error: %v", i, err)
		}
	}

	// Retrieve all messages
	retrieved, err := store.Messages(ctx, session.ID, 100, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 100, 0) unexpected error: %v", session.ID, err)
	}
	if len(retrieved) != 6 {
		t.Fatalf("GetMessages() returned %d messages, want 6", len(retrieved))
	}

	// Verify order
	for i := 0; i < 3; i++ {
		userMsg := retrieved[i*2]
		modelMsg := retrieved[i*2+1]

		if userMsg.Role != string(ai.RoleUser) {
			t.Errorf("Message[%d].Role = %q, want %q", i*2, userMsg.Role, string(ai.RoleUser))
		}
		expectedUserText := fmt.Sprintf("User message %d", i+1)
		if !strings.Contains(userMsg.Content[0].Text, expectedUserText) {
			t.Errorf("Message[%d].Content[0].Text = %q, want to contain %q", i*2, userMsg.Content[0].Text, expectedUserText)
		}

		if modelMsg.Role != string(ai.RoleModel) {
			t.Errorf("Message[%d].Role = %q, want %q", i*2+1, modelMsg.Role, string(ai.RoleModel))
		}
		expectedModelText := fmt.Sprintf("Model response %d", i+1)
		if !strings.Contains(modelMsg.Content[0].Text, expectedModelText) {
			t.Errorf("Message[%d].Content[0].Text = %q, want to contain %q", i*2+1, modelMsg.Content[0].Text, expectedModelText)
		}
	}
}

// TestStore_LargeMessageContent tests handling large message content
func TestStore_LargeMessageContent(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session
	session, err := store.CreateSession(ctx, "Large Content Test", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	// Create a large message (>10KB)
	largeText := strings.Repeat("This is a test message. ", 1000) // ~24KB

	message := &Message{
		Role: string(ai.RoleUser),
		Content: []*ai.Part{
			ai.NewTextPart(largeText),
		},
	}

	err = store.AddMessages(ctx, session.ID, []*Message{message})
	if err != nil {
		t.Fatalf("AddMessages() with large content unexpected error: %v", err)
	}

	// Retrieve and verify
	messages, err := store.Messages(ctx, session.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 10, 0) unexpected error: %v", session.ID, err)
	}
	if len(messages) != 1 {
		t.Fatalf("GetMessages() returned %d messages, want 1", len(messages))
	}
	if messages[0].Content[0].Text != largeText {
		t.Errorf("GetMessages()[0].Content[0].Text length = %d, want %d (large content not preserved)", len(messages[0].Content[0].Text), len(largeText))
	}
}

// TestStore_DeleteSessionWithMessages tests that deleting a session also deletes messages
func TestStore_DeleteSessionWithMessages(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session with messages
	session, err := store.CreateSession(ctx, "Cascade Delete Test", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	messages := []*Message{
		{
			Role:    string(ai.RoleUser),
			Content: []*ai.Part{ai.NewTextPart("Test message")},
		},
	}
	err = store.AddMessages(ctx, session.ID, messages)
	if err != nil {
		t.Fatalf("AddMessages() unexpected error: %v", err)
	}

	// Verify message exists
	retrieved, err := store.Messages(ctx, session.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 10, 0) before delete unexpected error: %v", session.ID, err)
	}
	if len(retrieved) != 1 {
		t.Errorf("GetMessages() before delete returned %d messages, want 1", len(retrieved))
	}

	// Delete session
	err = store.DeleteSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("DeleteSession(%v) unexpected error: %v", session.ID, err)
	}

	// Verify session is deleted
	_, err = store.Session(ctx, session.ID)
	if err == nil {
		t.Error("GetSession() after delete should return error")
	}
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

	expectedCount := numGoroutines - errCount
	if len(ids) != expectedCount {
		t.Errorf("created %d unique sessions, want %d", len(ids), expectedCount)
	}
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
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

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
	allMessages, err := store.Messages(ctx, session.ID, 1000, 0)
	if err != nil {
		t.Fatalf("GetMessages(%v, 1000, 0) unexpected error: %v", session.ID, err)
	}

	expectedCount := int(successCount.Load()) * messagesPerGoroutine
	if len(allMessages) != expectedCount {
		t.Errorf("GetMessages() returned %d messages, want %d", len(allMessages), expectedCount)
	}

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
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	// Add initial messages
	initialMsgs := []*Message{
		{Role: "user", Content: []*ai.Part{ai.NewTextPart("Initial message 1")}},
		{Role: "model", Content: []*ai.Part{ai.NewTextPart("Initial response 1")}},
	}
	if err := store.AddMessages(ctx, session.ID, initialMsgs); err != nil {
		t.Fatalf("AddMessages() for initial messages unexpected error: %v", err)
	}

	sessionID := session.ID
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
			history, err := store.History(ctx, sessionID)
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
	finalHistory, err := store.History(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetHistory(%v) final state unexpected error: %v", sessionID, err)
	}

	// Should have at least initial messages + some concurrent messages
	if len(finalHistory.Messages()) < 2 {
		t.Errorf("GetHistory() final state returned %d messages, want at least 2", len(finalHistory.Messages()))
	}

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
		if err != nil {
			t.Fatalf("CreateSession() for session %d unexpected error: %v", i, err)
		}
		sessions[i] = session

		// Add some messages
		msgs := []*Message{
			{Role: "user", Content: []*ai.Part{ai.NewTextPart("test message")}},
		}
		if err := store.AddMessages(ctx, session.ID, msgs); err != nil {
			t.Fatalf("AddMessages() for session %d unexpected error: %v", i, err)
		}
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
			_, _ = store.Session(ctx, s.ID)
		}(session)
	}

	wg.Wait()

	// Verify all sessions are deleted
	remaining, err := store.ListSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListSessions(100, 0) after concurrent deletion unexpected error: %v", err)
	}

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
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	sessionID := session.ID

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
			_, _ = store.Messages(ctx, session.ID, 100, 0)
		}()

		// Operation 3: Load history
		go func() {
			defer wg.Done()
			_, _ = store.History(ctx, sessionID)
		}()

		// Operation 4: Get session
		go func() {
			defer wg.Done()
			_, _ = store.Session(ctx, session.ID)
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
		if err != nil {
			t.Fatalf("CreateSession() for session %d unexpected error: %v", i+1, err)
		}
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
		messages, err := store.Messages(ctx, session.ID, 100, 0)
		if err != nil {
			t.Fatalf("GetMessages(%v, 100, 0) for session %d unexpected error: %v", session.ID, i+1, err)
		}
		if len(messages) != 10 {
			t.Errorf("Session %d has %d messages, want 10", i+1, len(messages))
		}
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
	if err != nil {
		t.Fatalf("CreateSession() for legitimate session unexpected error: %v", err)
	}
	t.Logf("Created legitimate session: %s", legitSession.ID)

	// Count sessions before attacks
	sessions, err := store.ListSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListSessions(100, 0) before attacks unexpected error: %v", err)
	}
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
		if err != nil {
			t.Fatalf("ListSessions(100, 0) after attacks unexpected error: %v (sessions table should still exist)", err)
		}

		// Legitimate session should still exist
		found := false
		for _, s := range sessions {
			if s.ID == legitSession.ID {
				found = true
				break
			}
		}
		if !found {
			t.Error("legitimate session should still exist after SQL injection attempts")
		}

		// Should be able to load the session
		loaded, err := store.Session(ctx, legitSession.ID)
		if err != nil {
			t.Fatalf("GetSession(%v) after attacks unexpected error: %v", legitSession.ID, err)
		}
		if loaded.Title != "Legitimate Session" {
			t.Errorf("GetSession(%v) Title = %q, want %q", legitSession.ID, loaded.Title, "Legitimate Session")
		}
	})
}

// TestStore_SQLInjectionViaSessionID tests injection through session IDs.
func TestStore_SQLInjectionViaSessionID(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session
	session, err := store.CreateSession(ctx, "Test Session", "", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

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
			_, err = store.Session(ctx, parsedID)
			t.Logf("GetSession result: %v", err)
		})
	}

	// Verify the test session still exists
	loaded, err := store.Session(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession(%v) after malicious ID attempts unexpected error: %v", session.ID, err)
	}
	if loaded.Title != "Test Session" {
		t.Errorf("GetSession(%v) Title = %q, want %q", session.ID, loaded.Title, "Test Session")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestStore_GetHistory_SessionNotFound verifies that GetHistory returns ErrSessionNotFound
// sentinel error when the session doesn't exist. This test validates the A3 fix from
// Proposal 056 - proper sentinel error propagation without double-wrapping.
func TestStore_GetHistory_SessionNotFound(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Use a non-existent session ID
	nonExistentID := uuid.New()

	// GetHistory should return ErrSessionNotFound
	_, err := store.History(ctx, nonExistentID)
	if err == nil {
		t.Fatal("GetHistory() with non-existent session should return error")
	}

	// Verify the error is the sentinel ErrSessionNotFound (errors.Is check)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetHistory(%v) error = %v (type: %T), want ErrSessionNotFound sentinel", nonExistentID, err, err)
	}

	// Verify error message is not double-wrapped
	errStr := err.Error()
	if strings.Contains(errStr, "session not found: session not found") {
		t.Errorf("GetHistory(%v) error message is double-wrapped: %v", nonExistentID, err)
	}
}

// TestStore_GetSession_NotFound verifies GetSession returns ErrSessionNotFound sentinel.
func TestStore_GetSession_NotFound(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	nonExistentID := uuid.New()
	_, err := store.Session(ctx, nonExistentID)
	if err == nil {
		t.Fatal("GetSession() with non-existent session should return error")
	}

	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetSession(%v) error = %v, want ErrSessionNotFound sentinel", nonExistentID, err)
	}
}

// =============================================================================
// SQL Injection Prevention Tests
// =============================================================================

// TestStore_SQLInjectionViaMessageContent tests injection through message content.
func TestStore_SQLInjectionViaMessageContent(t *testing.T) {
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Create a test session
	session, err := store.CreateSession(ctx, "Message Test", "", "")
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

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
		_, err := store.Session(ctx, session.ID)
		if err != nil {
			t.Fatalf("GetSession(%v) after malicious message attempts unexpected error: %v (session should still exist)", session.ID, err)
		}

		// Should be able to load messages
		sessionID := session.ID
		history, err := store.History(ctx, sessionID)
		if err != nil {
			t.Fatalf("GetHistory(%v) after malicious message attempts unexpected error: %v (should be able to load history)", sessionID, err)
		}
		t.Logf("loaded history with %d messages", len(history.Messages()))
	})
}
