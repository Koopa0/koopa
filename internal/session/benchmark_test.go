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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// Performance Expectations (from TESTING_STRATEGY_v3.md):
// - LoadHistory (100 msgs): < 50ms
// - SaveHistory: < 100ms

// BenchmarkStore_LoadHistory benchmarks loading conversation history.
// Run with: go test -tags=integration -bench=BenchmarkStore_LoadHistory -benchmem ./internal/session/...
func BenchmarkStore_LoadHistory(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 100) // 100 messages
	defer cleanup()

	sessionID := session.ID

	b.ResetTimer()
	for b.Loop() {
		_, err := store.LoadHistory(ctx, sessionID, "main")
		if err != nil {
			b.Fatalf("LoadHistory failed: %v", err)
		}
	}
}

// BenchmarkStore_LoadHistory_SmallSession benchmarks loading a small conversation.
func BenchmarkStore_LoadHistory_SmallSession(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 10) // 10 messages
	defer cleanup()

	sessionID := session.ID

	b.ResetTimer()
	for b.Loop() {
		if _, err := store.LoadHistory(ctx, sessionID, "main"); err != nil {
			b.Fatalf("LoadHistory failed: %v", err)
		}
	}
}

// BenchmarkStore_LoadHistory_LargeSession benchmarks loading a large conversation.
func BenchmarkStore_LoadHistory_LargeSession(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 500) // 500 messages
	defer cleanup()

	sessionID := session.ID

	b.ResetTimer()
	for b.Loop() {
		if _, err := store.LoadHistory(ctx, sessionID, "main"); err != nil {
			b.Fatalf("LoadHistory failed: %v", err)
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
	session, err := store.CreateSession(ctx, "Benchmark-AddMessages", "", "")
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
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

	b.ResetTimer()
	for i := range b.N {
		err := store.AddMessages(ctx, session.ID, messages[i])
		if err != nil {
			b.Fatalf("AddMessages failed at iteration %d: %v", i, err)
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

	createdSessionIDs := make([]string, 0, b.N)
	defer func() {
		for _, id := range createdSessionIDs {
			if parsed, err := parseBenchUUID(id); err == nil {
				_ = store.DeleteSession(context.Background(), parsed)
			}
		}
	}()

	b.ResetTimer()
	for i := range b.N {
		session, err := store.CreateSession(ctx, fmt.Sprintf("Benchmark-Session-%d", i), "test-model", "test-prompt")
		if err != nil {
			b.Fatalf("CreateSession failed at iteration %d: %v", i, err)
		}
		createdSessionIDs = append(createdSessionIDs, session.ID.String())
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
	session, err := store.CreateSession(ctx, "Benchmark-GetSession", "", "")
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer func() { _ = store.DeleteSession(ctx, session.ID) }()

	b.ResetTimer()
	for b.Loop() {
		_, err := store.GetSession(ctx, session.ID)
		if err != nil {
			b.Fatalf("GetSession failed: %v", err)
		}
	}
}

// BenchmarkStore_ListSessions benchmarks listing sessions.
func BenchmarkStore_ListSessions(b *testing.B) {
	ctx := context.Background()
	pool, cleanup := setupBenchmarkDB(b, ctx)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := New(sqlc.New(pool), pool, logger)

	// Create some test sessions
	for i := 0; i < 20; i++ {
		session, err := store.CreateSession(ctx, fmt.Sprintf("Benchmark-List-%d", i), "", "")
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}
		defer func(s *Session) { _ = store.DeleteSession(context.Background(), s.ID) }(session)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := store.ListSessions(ctx, 100, 0)
		if err != nil {
			b.Fatalf("ListSessions failed: %v", err)
		}
	}
}

// BenchmarkStore_GetMessages benchmarks getting messages from a session.
func BenchmarkStore_GetMessages(b *testing.B) {
	ctx := context.Background()
	store, session, cleanup := setupBenchmarkSession(b, ctx, 100)
	defer cleanup()

	b.ResetTimer()
	for b.Loop() {
		_, err := store.GetMessages(ctx, session.ID, 100, 0)
		if err != nil {
			b.Fatalf("GetMessages failed: %v", err)
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
	session, err := store.CreateSession(ctx, "Benchmark-Session", "", "")
	if err != nil {
		cleanup()
		b.Fatalf("Failed to create session: %v", err)
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
			b.Fatalf("Failed to add messages: %v", err)
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
		b.Fatalf("Failed to connect to database: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		b.Fatalf("Failed to ping database: %v", err)
	}

	cleanup := func() {
		// Clean up benchmark sessions
		_, _ = pool.Exec(context.Background(), "DELETE FROM sessions WHERE title LIKE 'Benchmark-%'")
		pool.Close()
	}

	return pool, cleanup
}

// parseBenchUUID is a helper to parse UUID strings for benchmarks.
func parseBenchUUID(s string) ([16]byte, error) {
	var u [16]byte
	if len(s) != 36 {
		return u, fmt.Errorf("invalid UUID length")
	}
	// Simple UUID parsing - parse each segment into temporary variables
	var a, b, c, d, e uint64
	if _, err := fmt.Sscanf(s, "%08x-%04x-%04x-%04x-%012x", &a, &b, &c, &d, &e); err != nil {
		return u, err
	}
	// Pack into [16]byte
	u[0] = byte(a >> 24)
	u[1] = byte(a >> 16)
	u[2] = byte(a >> 8)
	u[3] = byte(a)
	u[4] = byte(b >> 8)
	u[5] = byte(b)
	u[6] = byte(c >> 8)
	u[7] = byte(c)
	u[8] = byte(d >> 8)
	u[9] = byte(d)
	u[10] = byte(e >> 40)
	u[11] = byte(e >> 32)
	u[12] = byte(e >> 24)
	u[13] = byte(e >> 16)
	u[14] = byte(e >> 8)
	u[15] = byte(e)
	return u, nil
}
