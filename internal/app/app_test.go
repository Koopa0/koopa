package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/security"
	"golang.org/x/sync/errgroup"
)

// ============================================================================
// App.Close() Tests
// ============================================================================

func TestApp_Close(t *testing.T) {
	tests := []struct {
		name        string
		setupApp    func() *App
		expectError bool
	}{
		{
			name: "close with cancel function",
			setupApp: func() *App {
				ctx, cancel := context.WithCancel(context.Background())
				return &App{
					ctx:    ctx,
					cancel: cancel,
					DBPool: nil, // Don't mock pgxpool as it causes panic on close
				}
			},
			expectError: false,
		},
		{
			name: "close with nil DBPool",
			setupApp: func() *App {
				ctx, cancel := context.WithCancel(context.Background())
				return &App{
					ctx:    ctx,
					cancel: cancel,
					DBPool: nil,
				}
			},
			expectError: false,
		},
		{
			name: "close with nil cancel function",
			setupApp: func() *App {
				return &App{
					ctx:    context.Background(),
					cancel: nil,
					DBPool: nil,
				}
			},
			expectError: false,
		},
		{
			name: "close minimal app",
			setupApp: func() *App {
				return &App{}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.setupApp()
			err := app.Close()

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Verify context was canceled if cancel function existed
			if app.cancel != nil && app.ctx != nil {
				select {
				case <-app.ctx.Done():
					// Context was properly canceled
				default:
					t.Error("context was not canceled")
				}
			}
		})
	}
}

// ============================================================================
// App Struct Field Tests
// ============================================================================

func TestApp_Fields(t *testing.T) {
	t.Run("app with all fields set", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		g := genkit.Init(ctx)
		pathValidator, err := security.NewPath([]string{"."})
		if err != nil {
			t.Fatalf("failed to create path validator: %v", err)
		}

		app := &App{
			Config: &config.Config{
				ModelName: "gemini-2.0-flash-exp",
			},
			Genkit:        g,
			Embedder:      nil,
			DBPool:        nil,
			DocStore:      nil,
			Retriever:     nil,
			PathValidator: pathValidator,
			ctx:           ctx,
			cancel:        cancel,
		}

		// Verify fields are set
		if app.Config == nil {
			t.Error("expected Config to be set")
		}
		if app.Genkit == nil {
			t.Error("expected Genkit to be set")
		}
		if app.PathValidator == nil {
			t.Error("expected PathValidator to be set")
		}
		if app.ctx == nil {
			t.Error("expected ctx to be set")
		}
		if app.cancel == nil {
			t.Error("expected cancel to be set")
		}
	})
}

// ============================================================================
// Nil Safety Tests
// ============================================================================

func TestApp_NilSafety(t *testing.T) {
	tests := []struct {
		name string
		app  *App
	}{
		{
			name: "close nil app fields",
			app:  &App{},
		},
		{
			name: "close with only ctx",
			app: &App{
				ctx: context.Background(),
			},
		},
		{
			name: "close with only cancel",
			app: &App{
				cancel: func() {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			err := tt.app.Close()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// InitializeApp Integration Tests
// ============================================================================

func TestInitializeApp_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check required environment variables
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	// Skip if database is not available (PostgreSQL required)
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set - skipping integration test")
	}

	ctx := context.Background()
	cfg := &config.Config{
		ModelName:        "gemini-2.0-flash-exp",
		EmbedderModel:    "text-embedding-004",
		Temperature:      0.7,
		MaxTokens:        8192,
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "postgres",
		PostgresPassword: "",
		PostgresDBName:   "koopa_test",
		PostgresSSLMode:  "disable",
		PromptDir:        getPromptsDir(t),
	}

	// Test: InitializeApp should successfully create all components
	app, cleanup, err := InitializeApp(ctx, cfg)
	if err != nil {
		t.Fatalf("InitializeApp failed: %v", err)
	}
	defer cleanup()
	defer func() { _ = app.Close() }()

	// Verify all components are initialized
	if app == nil {
		t.Fatal("expected non-nil app")
		return
	}
	if app.Config == nil {
		t.Error("expected Config to be set")
	}
	if app.Genkit == nil {
		t.Error("expected Genkit to be set")
	}
	if app.Embedder == nil {
		t.Error("expected Embedder to be set")
	}
	if app.DBPool == nil {
		t.Error("expected DBPool to be set")
	}
	if app.DocStore == nil {
		t.Error("expected DocStore to be set")
	}
	if app.Retriever == nil {
		t.Error("expected Retriever to be set")
	}
	if app.SessionStore == nil {
		t.Error("expected SessionStore to be set")
	}
	if app.PathValidator == nil {
		t.Error("expected PathValidator to be set")
	}
	// Note: SystemIndexer was removed - system knowledge indexing is now
	// done via rag.IndexSystemKnowledge() function in newApp()

	// Verify database connection is functional
	if err := app.DBPool.Ping(ctx); err != nil {
		t.Errorf("database ping failed: %v", err)
	}
}

func TestInitializeApp_CleanupFunction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set - skipping integration test")
	}

	ctx := context.Background()
	cfg := &config.Config{
		ModelName:        "gemini-2.0-flash-exp",
		EmbedderModel:    "text-embedding-004",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "postgres",
		PostgresPassword: "",
		PostgresDBName:   "koopa_test",
		PostgresSSLMode:  "disable",
		PromptDir:        getPromptsDir(t),
	}

	app, cleanup, err := InitializeApp(ctx, cfg)
	if err != nil {
		t.Fatalf("InitializeApp failed: %v", err)
	}

	// Test: cleanup function should close database pool
	cleanup()

	// Verify pool is closed (ping should fail)
	if err := app.DBPool.Ping(ctx); err == nil {
		t.Error("expected database ping to fail after cleanup")
	}
}

func TestProvidePathValidator_Success(t *testing.T) {
	validator, err := providePathValidator()

	if err != nil {
		t.Fatalf("providePathValidator failed: %v", err)
	}
	if validator == nil {
		t.Fatal("expected non-nil path validator")
	}
}

// ============================================================================
// Shutdown and Lifecycle Tests
// ============================================================================

// TestApp_ShutdownTimeout tests that shutdown completes within reasonable time.
// Safety: Prevents hang during shutdown if background tasks don't respond to cancellation.
func TestApp_ShutdownTimeout(t *testing.T) {
	t.Run("graceful shutdown completes quickly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		app := &App{
			ctx:    ctx,
			cancel: cancel,
			DBPool: nil,
		}

		// Shutdown should complete quickly (no background tasks)
		done := make(chan struct{})
		go func() {
			_ = app.Close()
			close(done)
		}()

		select {
		case <-done:
			// Success: shutdown completed
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown timed out - potential deadlock")
		}
	})

	t.Run("shutdown with background goroutine", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		eg, egCtx := errgroup.WithContext(ctx)

		app := &App{
			ctx:    ctx,
			cancel: cancel,
			DBPool: nil,
			eg:     eg,
		}

		// Start a background task that respects context cancellation
		taskDone := make(chan struct{})
		app.Go(func() error {
			defer close(taskDone)
			<-egCtx.Done()
			return nil
		})

		// Shutdown should complete after background task exits
		done := make(chan struct{})
		go func() {
			_ = app.Close()
			close(done)
		}()

		select {
		case <-done:
			// Success: shutdown completed
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown timed out with background goroutine")
		}

		// Verify background task was properly terminated
		select {
		case <-taskDone:
			// Task completed
		default:
			t.Error("background task was not properly terminated")
		}
	})

	t.Run("shutdown timeout safety", func(t *testing.T) {
		// This test documents the expected behavior:
		// If a background task doesn't respond to context cancellation,
		// shutdown will block. This is intentional to prevent data loss.
		//
		// In production, consider adding a hard timeout:
		// - Use context.WithTimeout for background tasks
		// - Or implement a watchdog timer in Close()

		ctx, cancel := context.WithCancel(context.Background())
		app := &App{
			ctx:    ctx,
			cancel: cancel,
		}

		// Verify cancel is called during Close
		_ = app.Close()

		select {
		case <-ctx.Done():
			// Context was properly canceled
		default:
			t.Error("context was not canceled during shutdown")
		}
	})
}

// TestApp_Wait tests the Wait() method for background task completion.
func TestApp_Wait(t *testing.T) {
	t.Run("wait with nil errgroup returns nil", func(t *testing.T) {
		app := &App{eg: nil}
		err := app.Wait()
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	})

	t.Run("wait blocks until tasks complete", func(t *testing.T) {
		ctx := context.Background()
		eg, _ := errgroup.WithContext(ctx)

		app := &App{eg: eg}

		taskStarted := make(chan struct{})
		taskDone := make(chan struct{})

		app.Go(func() error {
			close(taskStarted)
			time.Sleep(50 * time.Millisecond)
			close(taskDone)
			return nil
		})

		<-taskStarted // Wait for task to start

		// Wait should block until task completes
		err := app.Wait()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		select {
		case <-taskDone:
			// Task completed before Wait returned
		default:
			t.Error("Wait returned before task completed")
		}
	})
}

// TestApp_Go tests the Go() method for starting background tasks.
func TestApp_Go(t *testing.T) {
	t.Run("go with nil errgroup does not panic", func(t *testing.T) {
		app := &App{eg: nil}

		// Should not panic
		app.Go(func() error {
			return nil
		})
	})

	t.Run("go tracks task in errgroup", func(t *testing.T) {
		ctx := context.Background()
		eg, _ := errgroup.WithContext(ctx)

		app := &App{eg: eg}

		executed := false
		app.Go(func() error {
			executed = true
			return nil
		})

		// Wait for task
		_ = app.Wait()

		if !executed {
			t.Error("task was not executed")
		}
	})
}

// ============================================================================
// Test Helpers
// ============================================================================

// findProjectRoot finds the project root directory by looking for go.mod.
func findProjectRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not determine caller filename")
	}

	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root (go.mod) not found")
		}
		dir = parent
	}
}

// getPromptsDir returns the absolute path to the prompts directory.
func getPromptsDir(t *testing.T) string {
	t.Helper()
	root, err := findProjectRoot()
	if err != nil || root == "" {
		t.Skip("Could not find project root")
	}
	return filepath.Join(root, "prompts")
}
