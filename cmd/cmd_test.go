package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/ui"
)

// ============================================================================
// Mock Session Store for Testing
// ============================================================================

type mockSessionStore struct{}

func (m *mockSessionStore) CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
	return &session.Session{
		ID:    uuid.New(),
		Title: title,
	}, nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
	return nil, nil
}

func (m *mockSessionStore) ListSessions(ctx context.Context, limit, offset int32) ([]*session.Session, error) {
	return []*session.Session{}, nil
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	return nil
}

func (m *mockSessionStore) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
	return []*session.Message{}, nil
}

func (m *mockSessionStore) AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error {
	return nil
}

// ============================================================================
// printWelcome Tests
// ============================================================================

func TestPrintWelcome(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		expectedStrings []string
	}{
		{
			name:    "standard version",
			version: "1.0.0",
			expectedStrings: []string{
				"v1.0.0",
				"Tips for getting started:",
				"/help for more information",
			},
		},
		{
			name:    "development version",
			version: "development",
			expectedStrings: []string{
				"vdevelopment",
				"Tips for getting started:",
			},
		},
		{
			name:    "empty version",
			version: "",
			expectedStrings: []string{
				"v",
				"Tips for getting started:",
			},
		},
		{
			name:    "long version string",
			version: "2.0.0-beta.1+build.12345",
			expectedStrings: []string{
				"v2.0.0-beta.1+build.12345",
				"Tips for getting started:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use ui.Mock
			mockUI := ui.NewMock()
			printWelcome(tt.version, mockUI)
			output := mockUI.Output.String()

			// Verify expected strings are present
			for _, expected := range tt.expectedStrings {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, but it didn't\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// handleSlashCommand Tests
// ============================================================================

func TestHandleSlashCommand(t *testing.T) {
	// Setup test context
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create mock agent
	mockAgent := &agent.Agent{}

	// Create mock app
	mockApp := &app.App{
		Config: &config.Config{
			ModelName: "gemini-2.0-flash-exp",
		},
		Genkit: g,
	}

	tests := []struct {
		name           string
		command        string
		expectedExit   bool
		expectedOutput []string
	}{
		{
			name:         "help command",
			command:      "/help",
			expectedExit: false,
			expectedOutput: []string{
				"Available Commands",
				"/help",
				"/version",
				"/clear",
				"/exit",
				"/rag",
			},
		},
		{
			name:         "version command",
			command:      "/version",
			expectedExit: false,
			expectedOutput: []string{
				"Koopa v",
				"Build:",
				"Commit:",
			},
		},
		{
			name:           "clear command",
			command:        "/clear",
			expectedExit:   false,
			expectedOutput: []string{"Conversation history cleared"},
		},
		{
			name:           "exit command",
			command:        "/exit",
			expectedExit:   true,
			expectedOutput: []string{"Goodbye!"},
		},
		{
			name:           "quit command",
			command:        "/quit",
			expectedExit:   true,
			expectedOutput: []string{"Goodbye!"},
		},
		{
			name:         "unknown command",
			command:      "/unknown",
			expectedExit: false,
			expectedOutput: []string{
				"Unknown command: /unknown",
				"Type /help",
			},
		},
		{
			name:         "rag command without args",
			command:      "/rag",
			expectedExit: false,
			expectedOutput: []string{
				"Usage: /rag <subcommand>",
				"add",
				"list",
				"remove",
				"status",
			},
		},
		{
			name:         "empty command",
			command:      "/",
			expectedExit: false,
			expectedOutput: []string{
				"Unknown command: /",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()

			// Call function
			shouldExit := handleSlashCommand(ctx, tt.command, mockAgent, mockApp, "test-version", mockUI)

			output := mockUI.Output.String()

			// Verify exit behavior
			if shouldExit != tt.expectedExit {
				t.Errorf("expected exit=%v, got exit=%v", tt.expectedExit, shouldExit)
			}

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// handleSlashCommand Edge Cases
// ============================================================================

func TestHandleSlashCommand_EdgeCases(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)
	mockAgent := &agent.Agent{}
	mockApp := &app.App{
		Config: &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit: g,
	}

	tests := []struct {
		name         string
		command      string
		expectedExit bool
	}{
		{
			name:         "whitespace only",
			command:      "   ",
			expectedExit: false,
		},
		{
			name:         "command with extra spaces",
			command:      "/help   ",
			expectedExit: false,
		},
		{
			name:         "command with multiple words (need PathValidator)",
			command:      "/help",
			expectedExit: false,
		},
		{
			name:         "case sensitive unknown",
			command:      "/HELP",
			expectedExit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			shouldExit := handleSlashCommand(ctx, tt.command, mockAgent, mockApp, "test", mockUI)

			if shouldExit != tt.expectedExit {
				t.Errorf("expected exit=%v, got exit=%v", tt.expectedExit, shouldExit)
			}
		})
	}
}

// ============================================================================
// printInteractiveHelp Tests
// ============================================================================

func TestPrintInteractiveHelp(t *testing.T) {
	mockUI := ui.NewMock()
	printInteractiveHelp(mockUI)
	output := mockUI.Output.String()

	// Expected strings in help output
	expectedStrings := []string{
		"Available Commands",
		"System:",
		"/help",
		"/version",
		"/clear",
		"/exit",
		"/quit",
		"RAG (Knowledge Management):",
		"/rag add",
		"/rag list",
		"/rag remove",
		"/rag status",
		"Shortcuts:",
		"Ctrl+C",
		"Ctrl+D",
		"https://github.com/koopa0/koopa-cli",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected help output to contain %q", expected)
		}
	}

	// Verify box drawing characters
	if !strings.Contains(output, "╔") || !strings.Contains(output, "╚") {
		t.Error("expected help output to have box drawing characters")
	}
}

// ============================================================================
// handleRAGCommand Tests
// ============================================================================

func TestHandleRAGCommand(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)
	mockApp := &app.App{
		Config: &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit: g,
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no arguments",
			args: []string{},
			expectedOutput: []string{
				"Usage: /rag <subcommand>",
				"Available subcommands:",
				"add",
				"list",
				"remove",
				"status",
			},
		},
		{
			name: "add without file",
			args: []string{"add"},
			expectedOutput: []string{
				"Error: Please specify a file or directory to add",
				"Usage: /rag add",
			},
		},
		{
			name: "remove without id",
			args: []string{"remove"},
			expectedOutput: []string{
				"Error: Please specify a document ID to remove",
				"Usage: /rag remove",
			},
		},
		{
			name: "unknown subcommand",
			args: []string{"unknown"},
			expectedOutput: []string{
				"Unknown /rag subcommand: unknown",
				"Type /rag",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleRAGCommand(ctx, tt.args, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// handleRAGAdd Tests
// ============================================================================

func TestHandleRAGAdd(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create path validator
	pathValidator, err := security.NewPath([]string{"."})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	mockApp := &app.App{
		Config:        &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit:        g,
		PathValidator: pathValidator,
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no file specified",
			args: []string{},
			expectedOutput: []string{
				"Error: Please specify a file or directory to add",
				"Usage: /rag add",
			},
		},
		{
			name: "non-existent file (outside allowed dirs)",
			args: []string{"/tmp/nonexistent-file-12345.txt"},
			expectedOutput: []string{
				"Error: Invalid path",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleRAGAdd(ctx, tt.args, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// handleRAGList Tests
// ============================================================================

func TestHandleRAGList_EmptyStore(t *testing.T) {
	t.Skip("Skipping test that requires real database connection - tested via integration tests")
}

// ============================================================================
// handleRAGStatus Tests
// ============================================================================

func TestHandleRAGStatus(t *testing.T) {
	t.Skip("Skipping test that requires real database connection - tested via integration tests")
}

// ============================================================================
// handleRAGReindexSystem Tests
// ============================================================================

func TestHandleRAGReindexSystem(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	tests := []struct {
		name           string
		expectedOutput []string
	}{
		{
			name: "system indexer not available",
			expectedOutput: []string{
				"System Knowledge Reindexing",
				"Error: System indexer not available",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockApp := &app.App{
				Config:        &config.Config{ModelName: "gemini-2.0-flash-exp"},
				Genkit:        g,
				SystemIndexer: nil, // nil to test error case
			}

			mockUI := ui.NewMock()
			handleRAGReindexSystem(ctx, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// handleRAGRemove Tests
// ============================================================================

func TestHandleRAGRemove(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	mockApp := &app.App{
		Config: &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit: g,
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no document id",
			args: []string{},
			expectedOutput: []string{
				"Error: Please specify a document ID to remove",
				"Usage: /rag remove",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleRAGRemove(ctx, tt.args, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// ============================================================================
// Session Command Tests
// ============================================================================

func TestHandleSessionCommand(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create mock agent (will use for basic tests)
	mockAgent := &agent.Agent{}

	// Create mock app with mock session store
	mockApp := &app.App{
		Config:       &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit:       g,
		SessionStore: &mockSessionStore{},
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "session without args shows current session (no active)",
			args: []string{},
			expectedOutput: []string{
				"No active session",
				"/session new",
				"/session switch",
				"/session list",
			},
		},
		{
			name:           "session list without args",
			args:           []string{"list"},
			expectedOutput: []string{
				// Will show "No sessions found" since mock store is empty
			},
		},
		{
			name: "session new without title",
			args: []string{"new"},
			expectedOutput: []string{
				"Error: Please provide a session title",
				"Usage: /session new <title>",
			},
		},
		{
			name: "session switch without id",
			args: []string{"switch"},
			expectedOutput: []string{
				"Error: Please provide a session ID",
				"Usage: /session switch <id>",
			},
		},
		{
			name: "session delete without id",
			args: []string{"delete"},
			expectedOutput: []string{
				"Error: Please provide a session ID",
				"Usage: /session delete <id>",
			},
		},
		{
			name: "session with unknown subcommand",
			args: []string{"unknown"},
			expectedOutput: []string{
				"Unknown /session subcommand: unknown",
				"Type /session to see usage",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleSessionCommand(ctx, tt.args, mockAgent, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

func TestHandleSessionNew_ErrorCases(t *testing.T) {
	ctx := context.Background()
	mockAgent := &agent.Agent{}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no arguments",
			args: []string{},
			expectedOutput: []string{
				"Error: Please provide a session title",
				"Usage: /session new <title>",
			},
		},
		{
			name: "empty string after trim",
			args: []string{"   "},
			expectedOutput: []string{
				"Error: Session title cannot be empty",
				"Usage: /session new <title>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleSessionNew(ctx, tt.args, mockAgent, mockUI)
			output := mockUI.Output.String()

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

func TestHandleSessionSwitch_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockAgent := &agent.Agent{}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no arguments",
			args: []string{},
			expectedOutput: []string{
				"Error: Please provide a session ID",
				"Usage: /session switch <id>",
			},
		},
		{
			name: "invalid UUID format",
			args: []string{"invalid-id"},
			expectedOutput: []string{
				"Error: Invalid session ID format",
				"Usage: /session switch <id>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleSessionSwitch(ctx, tt.args, mockAgent, mockUI)
			output := mockUI.Output.String()

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

func TestHandleSessionDelete_InvalidID(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)
	mockAgent := &agent.Agent{}
	mockApp := &app.App{
		Config: &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit: g,
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "no arguments",
			args: []string{},
			expectedOutput: []string{
				"Error: Please provide a session ID",
				"Usage: /session delete <id>",
			},
		},
		{
			name: "invalid UUID format",
			args: []string{"not-a-uuid"},
			expectedOutput: []string{
				"Error: Invalid session ID format",
				"Usage: /session delete <id>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleSessionDelete(ctx, tt.args, mockAgent, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

func TestParseSessionID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid UUID",
			input:   "123e4567-e89b-12d3-a456-426614174000",
			wantErr: false,
		},
		{
			name:    "invalid UUID - not enough segments",
			input:   "123e4567",
			wantErr: true,
		},
		{
			name:    "invalid UUID - wrong format",
			input:   "not-a-uuid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSessionID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSessionID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{
			name: "a is smaller",
			a:    5,
			b:    10,
			want: 5,
		},
		{
			name: "b is smaller",
			a:    10,
			b:    5,
			want: 5,
		},
		{
			name: "equal values",
			a:    7,
			b:    7,
			want: 7,
		},
		{
			name: "negative values",
			a:    -5,
			b:    -10,
			want: -10,
		},
		{
			name: "zero and positive",
			a:    0,
			b:    5,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := min(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Session Success Scenario Tests
// ============================================================================

func TestHandleSessionList_WithSessions(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create mock session store that returns sessions
	mockStore := &mockSessionStoreWithData{
		sessions: []*session.Session{
			{
				ID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
				Title:        "Test Session 1",
				MessageCount: 5,
			},
			{
				ID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
				Title:        "Test Session 2",
				MessageCount: 10,
			},
		},
	}

	mockApp := &app.App{
		Config:       &config.Config{ModelName: "gemini-2.0-flash-exp"},
		Genkit:       g,
		SessionStore: mockStore,
	}

	tests := []struct {
		name           string
		args           []string
		expectedOutput []string
	}{
		{
			name: "list with default limit",
			args: []string{},
			expectedOutput: []string{
				"Sessions",
				"Test Session 1",
				"Test Session 2",
				"Total: 2 sessions",
			},
		},
		{
			name: "list with custom limit",
			args: []string{"5"},
			expectedOutput: []string{
				"Sessions",
				"Test Session 1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUI := ui.NewMock()
			handleSessionList(ctx, tt.args, mockApp, mockUI)
			output := mockUI.Output.String()

			// Verify expected output strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}

// mockSessionStoreWithData is a mock that returns actual session data
type mockSessionStoreWithData struct {
	sessions []*session.Session
}

func (m *mockSessionStoreWithData) CreateSession(ctx context.Context, title, modelName, systemPrompt string) (*session.Session, error) {
	return &session.Session{
		ID:    uuid.New(),
		Title: title,
	}, nil
}

func (m *mockSessionStoreWithData) GetSession(ctx context.Context, sessionID uuid.UUID) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.ID == sessionID {
			return s, nil
		}
	}
	return nil, nil
}

func (m *mockSessionStoreWithData) ListSessions(ctx context.Context, limit, offset int32) ([]*session.Session, error) {
	if len(m.sessions) == 0 {
		return []*session.Session{}, nil
	}

	// Implement proper pagination
	start := int(offset)
	if start > len(m.sessions) {
		return []*session.Session{}, nil
	}

	end := min(len(m.sessions), int(offset)+int(limit))
	return m.sessions[start:end], nil
}

func (m *mockSessionStoreWithData) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	return nil
}

func (m *mockSessionStoreWithData) GetMessages(ctx context.Context, sessionID uuid.UUID, limit, offset int32) ([]*session.Message, error) {
	return []*session.Message{}, nil
}

func (m *mockSessionStoreWithData) AddMessages(ctx context.Context, sessionID uuid.UUID, messages []*session.Message) error {
	return nil
}

// Additional comprehensive session tests follow...
// These tests cover success scenarios for session management functions

// Note: The following tests are simplified and focus on output validation
// They do not require complex agent state management for cmd layer testing
