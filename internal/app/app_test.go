package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/testutil"
)

func TestApp_Close(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *App
		expectError bool
	}{
		{
			name: "close with cancel function",
			setup: func() *App {
				_, cancel := context.WithCancel(context.Background())
				return &App{cancel: cancel}
			},
		},
		{
			name: "close with nil cancel",
			setup: func() *App {
				return &App{cancel: nil}
			},
		},
		{
			name: "close with cleanup functions",
			setup: func() *App {
				return &App{
					dbCleanup:   func() {},
					otelCleanup: func() {},
				}
			},
		},
		{
			name: "close minimal app",
			setup: func() *App {
				return &App{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.setup()
			err := a.Close()

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Close() unexpected error: %v", err)
			}
		})
	}
}

func TestApp_Fields(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		g := genkit.Init(ctx)
		pathValidator, err := security.NewPath([]string{"."}, nil)
		if err != nil {
			t.Fatalf("security.NewPath() error: %v", err)
		}

		a := &App{
			Config: &config.Config{
				ModelName: "gemini-2.0-flash-exp",
			},
			Genkit:        g,
			Embedder:      nil,
			DBPool:        nil,
			DocStore:      nil,
			Retriever:     nil,
			PathValidator: pathValidator,
			cancel:        cancel,
		}

		if a.Config == nil {
			t.Error("App.Config = nil, want non-nil")
		}
		if a.Genkit == nil {
			t.Error("App.Genkit = nil, want non-nil")
		}
		if a.PathValidator == nil {
			t.Error("App.PathValidator = nil, want non-nil")
		}
		if a.cancel == nil {
			t.Error("App.cancel = nil, want non-nil")
		}
	})
}

func TestApp_NilSafety(t *testing.T) {
	tests := []struct {
		name string
		a    *App
	}{
		{
			name: "close nil fields",
			a:    &App{},
		},
		{
			name: "close with only cancel",
			a:    &App{cancel: func() {}},
		},
		{
			name: "close with only cleanup",
			a:    &App{dbCleanup: func() {}, otelCleanup: func() {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.a.Close()
			if err != nil {
				t.Errorf("Close() unexpected error: %v", err)
			}
		})
	}
}

func TestApp_Close_ShutdownOrder(t *testing.T) {
	t.Run("cleanup called after cancel", func(t *testing.T) {
		var order []string

		a := &App{
			cancel:      func() { order = append(order, "cancel") },
			dbCleanup:   func() { order = append(order, "db") },
			otelCleanup: func() { order = append(order, "otel") },
		}

		_ = a.Close()

		if len(order) != 3 {
			t.Fatalf("Close() operations = %d, want 3: %v", len(order), order)
		}
		if order[0] != "cancel" {
			t.Errorf("order[0] = %q, want %q", order[0], "cancel")
		}
		if order[1] != "db" {
			t.Errorf("order[1] = %q, want %q", order[1], "db")
		}
		if order[2] != "otel" {
			t.Errorf("order[2] = %q, want %q", order[2], "otel")
		}
	})

	t.Run("idempotent close", func(t *testing.T) {
		callCount := 0
		a := &App{
			cancel:      func() { callCount++ },
			dbCleanup:   func() { callCount++ },
			otelCleanup: func() { callCount++ },
		}

		_ = a.Close()
		_ = a.Close() // second call should be no-op

		if callCount != 3 {
			t.Errorf("Close() twice: call count = %d, want 3 (second Close should be no-op)", callCount)
		}
	})
}

func TestSetup_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set")
	}
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set")
	}

	ctx := context.Background()
	cfg := &config.Config{
		ModelName:        "gemini-2.0-flash-exp",
		EmbedderModel:    "gemini-embedding-001",
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

	a, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	defer func() { _ = a.Close() }()

	if a.Config == nil {
		t.Error("Setup().Config = nil, want non-nil")
	}
	if a.Genkit == nil {
		t.Error("Setup().Genkit = nil, want non-nil")
	}
	if a.Embedder == nil {
		t.Error("Setup().Embedder = nil, want non-nil")
	}
	if a.DBPool == nil {
		t.Error("Setup().DBPool = nil, want non-nil")
	}
	if a.DocStore == nil {
		t.Error("Setup().DocStore = nil, want non-nil")
	}
	if a.Retriever == nil {
		t.Error("Setup().Retriever = nil, want non-nil")
	}
	if a.SessionStore == nil {
		t.Error("Setup().SessionStore = nil, want non-nil")
	}
	if a.PathValidator == nil {
		t.Error("Setup().PathValidator = nil, want non-nil")
	}

	// Verify database connection is functional
	if err := a.DBPool.Ping(ctx); err != nil {
		t.Errorf("pinging database: %v", err)
	}
}

func TestSetup_CleanupOnClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set")
	}
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set")
	}

	ctx := context.Background()
	cfg := &config.Config{
		ModelName:        "gemini-2.0-flash-exp",
		EmbedderModel:    "gemini-embedding-001",
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "postgres",
		PostgresPassword: "",
		PostgresDBName:   "koopa_test",
		PostgresSSLMode:  "disable",
		PromptDir:        getPromptsDir(t),
	}

	a, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}

	pool := a.DBPool

	// Close should release DB pool
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Verify pool is closed (ping should fail)
	if err := pool.Ping(ctx); err == nil {
		t.Error("pool.Ping() after Close() = nil, want error")
	}
}

func TestProvidePathValidator_Success(t *testing.T) {
	validator, err := providePathValidator()
	if err != nil {
		t.Fatalf("providePathValidator() error: %v", err)
	}
	if validator == nil {
		t.Fatal("providePathValidator() returned nil")
	}
}

func TestApp_ShutdownTimeout(t *testing.T) {
	t.Run("graceful shutdown completes quickly", func(t *testing.T) {
		_, cancel := context.WithCancel(context.Background())
		a := &App{cancel: cancel}

		done := make(chan struct{})
		go func() {
			_ = a.Close()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown timed out")
		}
	})
}

func getPromptsDir(t *testing.T) string {
	t.Helper()
	root, err := testutil.FindProjectRoot()
	if err != nil || root == "" {
		t.Skip("could not find project root")
	}
	return filepath.Join(root, "prompts")
}
