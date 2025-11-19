package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDBContainer wraps a PostgreSQL test container
type TestDBContainer struct {
	Container *postgres.PostgresContainer
	Pool      *pgxpool.Pool
	ConnStr   string
}

// SetupTestDB creates a PostgreSQL container for testing
// Returns a TestDBContainer and a cleanup function
func SetupTestDB(t *testing.T) (*TestDBContainer, func()) {
	t.Helper()

	ctx := context.Background()

	// Create PostgreSQL container with pgvector support
	pgContainer, err := postgres.Run(ctx,
		"pgvector/pgvector:pg16",
		postgres.WithDatabase("koopa_test"),
		postgres.WithUsername("koopa_test"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Create connection pool
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create connection pool: %v", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Run migrations
	if err := runMigrations(ctx, pool); err != nil {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	container := &TestDBContainer{
		Container: pgContainer,
		Pool:      pool,
		ConnStr:   connStr,
	}

	cleanup := func() {
		if pool != nil {
			pool.Close()
		}
		if pgContainer != nil {
			_ = pgContainer.Terminate(context.Background())
		}
	}

	return container, cleanup
}

// runMigrations runs database migrations
// This is a simplified version - in production, you'd use a migration tool
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Read and execute migration files in order
	migrationFiles := []string{
		"../../db/migrations/000001_init_schema.up.sql",
		"../../db/migrations/000002_create_sessions.up.sql",
	}

	for _, migrationPath := range migrationFiles {
		migrationSQL, err := os.ReadFile(migrationPath)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", migrationPath, err)
		}

		_, err = pool.Exec(ctx, string(migrationSQL))
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", migrationPath, err)
		}
	}

	return nil
}

// TestAgentFramework provides a complete test environment for Agent integration tests
type TestAgentFramework struct {
	// Database
	DBContainer *TestDBContainer

	// Core components
	Agent          *Agent
	KnowledgeStore *knowledge.Store
	SystemIndexer  *knowledge.SystemKnowledgeIndexer
	SessionStore   *session.Store
	Genkit         *genkit.Genkit
	Embedder       ai.Embedder
	Retriever      ai.Retriever
	Config         *config.Config

	// Test session
	SessionID uuid.UUID

	// Cleanup function
	cleanup func()
}

// SetupTestAgent creates a complete Agent test environment with testcontainers
func SetupTestAgent(t *testing.T) (*TestAgentFramework, func()) {
	t.Helper()

	// Check for required API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()

	// 1. Setup test database
	dbContainer, dbCleanup := SetupTestDB(t)

	// 2. Initialize Genkit with Google AI plugin
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("../../prompts"))

	// 3. Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, "text-embedding-004")

	// 4. Create knowledge store
	knowledgeStore := knowledge.New(dbContainer.Pool, embedder, slog.Default())

	// 5. Create system knowledge indexer
	systemIndexer := knowledge.NewSystemKnowledgeIndexer(knowledgeStore, slog.Default())

	// 6. Create config
	cfg := &config.Config{
		ModelName:        "gemini-2.5-flash",
		EmbedderModel:    "text-embedding-004",
		Temperature:      0.7,
		MaxTokens:        8192,
		RAGTopK:          5,
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "koopa_test",
		PostgresPassword: "test_password",
		PostgresDBName:   "koopa_test",
		PostgresSSLMode:  "disable",
	}

	// 7. Create session store
	sessionStore := session.New(dbContainer.Pool, slog.Default())

	// 8. Create test session
	testSession, err := sessionStore.CreateSession(ctx, "Integration Test Session", cfg.ModelName, "")
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create test session: %v", err)
	}
	sessionID := testSession.ID

	// 9. Create retriever for RAG
	retrieverBuilder := rag.New(knowledgeStore)
	retriever := retrieverBuilder.DefineConversation(g, "integration-test-retriever")

	// 10. Create Agent
	agent, err := New(ctx, cfg, g, retriever,
		WithSessionStore(sessionStore),
		WithKnowledgeStore(knowledgeStore),
		WithLogger(slog.Default()),
	)
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create agent: %v", err)
	}

	framework := &TestAgentFramework{
		DBContainer:    dbContainer,
		Agent:          agent,
		KnowledgeStore: knowledgeStore,
		SystemIndexer:  systemIndexer,
		SessionStore:   sessionStore,
		Genkit:         g,
		Embedder:       embedder,
		Retriever:      retriever,
		Config:         cfg,
		SessionID:      sessionID,
		cleanup:        dbCleanup,
	}

	cleanup := func() {
		dbCleanup()
	}

	return framework, cleanup
}

// IndexSystemKnowledge indexes system knowledge for testing
func (f *TestAgentFramework) IndexSystemKnowledge(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	count, err := f.SystemIndexer.IndexAll(ctx)
	if err != nil {
		t.Fatalf("Failed to index system knowledge: %v", err)
	}
	t.Logf("Indexed %d system knowledge documents", count)
}
