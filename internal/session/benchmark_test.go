//go:build integration
// +build integration

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa/internal/sqlc"
)

// Performance Expectations (from TESTING_STRATEGY_v3.md):
// - GetHistory (100 msgs): < 50ms
// - SaveHistory: < 100ms

// BenchmarkStore_GetHistory benchmarks loading conversation history.
// Run with: go test -tags=integration -bench=BenchmarkStore_GetHistory -benchmem ./internal/session/...
func BenchmarkStore_GetHistory(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 100) // 100 messages
	defer cleanup()

	sessionID := session.ID

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := store.History(ctx, sessionID)
		if err != nil {
			b.Fatalf("History(): %v", err)
		}
	}
}

// BenchmarkStore_GetHistory_SmallSession benchmarks loading a small conversation.
func BenchmarkStore_GetHistory_SmallSession(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 10) // 10 messages
	defer cleanup()

	sessionID := session.ID

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := store.History(ctx, sessionID); err != nil {
			b.Fatalf("History(): %v", err)
		}
	}
}

// BenchmarkStore_GetHistory_LargeSession benchmarks loading a large conversation.
func BenchmarkStore_GetHistory_LargeSession(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 500) // 500 messages
	defer cleanup()

	sessionID := session.ID

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := store.History(ctx, sessionID); err != nil {
			b.Fatalf("History(): %v", err)
		}
	}
}

// BenchmarkStore_AddMessages benchmarks adding messages to a session.
func BenchmarkStore_AddMessages(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create a test session
	session, err := store.CreateSession(ctx, "bench-owner", "Benchmark-AddMessages")
	if err != nil {
		b.Fatalf("creating session: %v", err)
	}
	defer func() { _ = store.DeleteSession(ctx, session.ID) }()

	// Prepare messages
	messages := make([][]*Message, b.N)
	for i := range b.N {
		messages[i] = []*Message{
			{
				Role:    "user",
				Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Benchmark message %d", i))},
			},
			{
				Role:    "model",
				Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Benchmark response %d", i))},
			},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		err := store.AddMessages(ctx, session.ID, messages[i])
		if err != nil {
			b.Fatalf("AddMessages failed at iteration %d: %v", i, err)
		}
	}
}

// BenchmarkStore_AppendMessages benchmarks the Genkit-type message appending.
func BenchmarkStore_AppendMessages(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create a test session
	session, err := store.CreateSession(ctx, "bench-owner", "Benchmark-AppendMessages")
	if err != nil {
		b.Fatalf("creating session: %v", err)
	}
	defer func() { _ = store.DeleteSession(ctx, session.ID) }()

	// Prepare ai.Message slices
	messages := make([][]*ai.Message, b.N)
	for i := range b.N {
		messages[i] = []*ai.Message{
			ai.NewUserMessage(ai.NewTextPart(fmt.Sprintf("Benchmark message %d", i))),
			ai.NewModelMessage(ai.NewTextPart(fmt.Sprintf("Benchmark response %d", i))),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		err := store.AppendMessages(ctx, session.ID, messages[i])
		if err != nil {
			b.Fatalf("AppendMessages failed at iteration %d: %v", i, err)
		}
	}
}

// BenchmarkStore_CreateSession benchmarks session creation.
func BenchmarkStore_CreateSession(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	createdSessionIDs := make([]uuid.UUID, 0, b.N)
	defer func() {
		for _, id := range createdSessionIDs {
			_ = store.DeleteSession(context.Background(), id)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		session, err := store.CreateSession(ctx, "bench-owner", fmt.Sprintf("Benchmark-Session-%d", i))
		if err != nil {
			b.Fatalf("CreateSession failed at iteration %d: %v", i, err)
		}
		createdSessionIDs = append(createdSessionIDs, session.ID)
	}
}

// BenchmarkStore_GetSession benchmarks getting a session by ID.
func BenchmarkStore_GetSession(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create a test session
	session, err := store.CreateSession(ctx, "bench-owner", "Benchmark-GetSession")
	if err != nil {
		b.Fatalf("creating session: %v", err)
	}
	defer func() { _ = store.DeleteSession(ctx, session.ID) }()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := store.Session(ctx, session.ID)
		if err != nil {
			b.Fatalf("Session(): %v", err)
		}
	}
}

// BenchmarkStore_Sessions benchmarks listing sessions.
func BenchmarkStore_Sessions(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create some test sessions
	for i := 0; i < 20; i++ {
		session, err := store.CreateSession(ctx, "bench-owner", fmt.Sprintf("Benchmark-List-%d", i))
		if err != nil {
			b.Fatalf("creating session: %v", err)
		}
		defer func(s *Session) { _ = store.DeleteSession(context.Background(), s.ID) }(session)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := store.Sessions(ctx, "bench-owner", 100, 0)
		if err != nil {
			b.Fatalf("Sessions() unexpected error: %v", err)
		}
	}
}

// BenchmarkStore_GetMessages benchmarks getting messages from a session.
func BenchmarkStore_GetMessages(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 100)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := store.Messages(ctx, session.ID, 100, 0)
		if err != nil {
			b.Fatalf("Messages(): %v", err)
		}
	}
}

// setupBenchmarkSession creates a session with pre-loaded messages for benchmarking.
func setupBenchmarkSession(b *testing.B, ctx context.Context, numMessages int) (*Store, *Session, func()) {
	b.Helper()

	pool, cleanup := setupBenchmarkDB(b, ctx)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create a test session
	session, err := store.CreateSession(ctx, "bench-owner", "Benchmark-Session")
	if err != nil {
		cleanup()
		b.Fatalf("creating session: %v", err)
	}

	// Pre-load messages (in batches for efficiency)
	batchSize := 50
	for i := 0; i < numMessages; i += batchSize {
		end := i + batchSize
		if end > numMessages {
			end = numMessages
		}

		messages := make([]*Message, end-i)
		for j := i; j < end; j++ {
			role := "user"
			if j%2 == 1 {
				role = "model"
			}
			messages[j-i] = &Message{
				Role:    role,
				Content: []*ai.Part{ai.NewTextPart(fmt.Sprintf("Benchmark message %d", j))},
			}
		}

		if err := store.AddMessages(ctx, session.ID, messages); err != nil {
			cleanup()
			b.Fatalf("adding messages: %v", err)
		}
	}

	cleanupAll := func() {
		_ = store.DeleteSession(context.Background(), session.ID)
		cleanup()
	}

	return store, session, cleanupAll
}

// setupBenchmarkDB creates a test database connection for benchmarks.
func setupBenchmarkDB(b *testing.B, ctx context.Context) (*pgxpool.Pool, func()) {
	b.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://localhost/koopa_test?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		b.Fatalf("connecting to database: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		b.Fatalf("pinging database: %v", err)
	}

	cleanup := func() {
		// Clean up benchmark sessions
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE title LIKE 'Benchmark-%'")
		pool.Close()
	}

	return pool, cleanup
}
