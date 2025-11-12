package app

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
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

			// Verify context was cancelled if cancel function existed
			if app.cancel != nil && app.ctx != nil {
				select {
				case <-app.ctx.Done():
					// Context was properly cancelled
				default:
					t.Error("context was not cancelled")
				}
			}
		})
	}
}

// ============================================================================
// App.CreateAgent() Tests
// ============================================================================

// mockRetriever is a simple mock for ai.Retriever
type mockRetriever struct {
	ai.Retriever
}

func TestApp_CreateAgent(t *testing.T) {
	tests := []struct {
		name        string
		setupApp    func(t *testing.T) *App
		retriever   ai.Retriever
		skipTest    bool
		expectError bool
		errorMsg    string
	}{
		{
			name: "create agent with valid app",
			setupApp: func(t *testing.T) *App {
				ctx := context.Background()

				// Initialize Genkit (required for agent creation)
				g := genkit.Init(ctx)

				return &App{
					Config: &config.Config{
						ModelName:   "gemini-2.0-flash-exp",
						Temperature: 0.7,
						MaxTokens:   8192,
					},
					Genkit: g,
					ctx:    ctx,
				}
			},
			retriever:   &mockRetriever{},
			skipTest:    true, // Skip: requires GEMINI_API_KEY env var
			expectError: false,
		},
		{
			name: "create agent with nil config",
			setupApp: func(t *testing.T) *App {
				ctx := context.Background()
				g := genkit.Init(ctx)

				return &App{
					Config: nil,
					Genkit: g,
					ctx:    ctx,
				}
			},
			retriever:   &mockRetriever{},
			expectError: true,
			errorMsg:    "config is required",
		},
		{
			name: "create agent with nil genkit",
			setupApp: func(t *testing.T) *App {
				return &App{
					Config: &config.Config{
						ModelName: "gemini-2.0-flash-exp",
					},
					Genkit: nil,
					ctx:    context.Background(),
				}
			},
			retriever:   &mockRetriever{},
			expectError: true,
			errorMsg:    "genkit is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip("Skipping test that requires GEMINI_API_KEY environment variable")
				return
			}

			app := tt.setupApp(t)
			ctx := context.Background()

			ag, err := app.CreateAgent(ctx, tt.retriever)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if ag != nil {
					t.Error("expected nil agent on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ag == nil {
					t.Error("expected non-nil agent")
				}
			}
		})
	}
}

// ============================================================================
// Integration-style Tests
// ============================================================================

func TestApp_Lifecycle(t *testing.T) {
	t.Run("create and close app", func(t *testing.T) {
		t.Skip("Skipping integration test that requires GEMINI_API_KEY")
	})
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
			Knowledge:     &knowledge.Store{},
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
// Helper to verify agent.Agent interface compliance
// ============================================================================

func TestCreateAgent_ReturnsCorrectType(t *testing.T) {
	t.Skip("Skipping test that requires GEMINI_API_KEY environment variable")
}
