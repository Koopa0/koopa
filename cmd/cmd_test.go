package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/security"
)

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
				"Koopa v1.0.0",
				"AI Personal Assistant powered by Gemini",
				"Type /help for commands",
				"Ctrl+D to exit",
			},
		},
		{
			name:    "development version",
			version: "development",
			expectedStrings: []string{
				"Koopa vdevelopment",
				"AI Personal Assistant",
			},
		},
		{
			name:    "empty version",
			version: "",
			expectedStrings: []string{
				"Koopa v",
				"AI Personal Assistant",
			},
		},
		{
			name:    "long version string",
			version: "2.0.0-beta.1+build.12345",
			expectedStrings: []string{
				"Koopa v2.0.0-beta.1+build.12345",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Call function
			printWelcome(tt.version)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			// Verify expected strings are present
			for _, expected := range tt.expectedStrings {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, but it didn't\nGot: %s", expected, output)
				}
			}

			// Verify output has box drawing characters
			if !strings.Contains(output, "╔") || !strings.Contains(output, "╗") {
				t.Error("expected output to contain box drawing characters")
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
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Call function
			shouldExit := handleSlashCommand(ctx, tt.command, mockAgent, mockApp, "test-version")

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

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
			// Capture stdout to prevent test output pollution
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			shouldExit := handleSlashCommand(ctx, tt.command, mockAgent, mockApp, "test")

			w.Close()
			os.Stdout = oldStdout
			_, _ = io.Copy(io.Discard, r)

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
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printInteractiveHelp()

	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

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
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			handleRAGCommand(ctx, tt.args, mockApp)

			w.Close()
			os.Stdout = oldStdout

			// Read output
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

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
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			handleRAGAdd(ctx, tt.args, mockApp)

			w.Close()
			os.Stdout = oldStdout

			// Read output
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

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
	t.Skip("Skipping test that requires real knowledge store - tested via integration tests")
}

// ============================================================================
// handleRAGStatus Tests
// ============================================================================

func TestHandleRAGStatus(t *testing.T) {
	t.Skip("Skipping test that requires real knowledge store - tested via integration tests")
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
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			handleRAGRemove(ctx, tt.args, mockApp)

			w.Close()
			os.Stdout = oldStdout

			// Read output
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			// Verify expected strings
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q\nGot: %s", expected, output)
				}
			}
		})
	}
}
