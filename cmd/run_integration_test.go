package cmd

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/ui"
)

// TestCLISession_Example demonstrates how to use CLISession for E2E testing
// This replaces time.Sleep() with ExpectString() for reliable testing
func TestCLISession_Example(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// Create pipes for I/O
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	// IMPORTANT: Ensure all pipe ends are closed to prevent resource leaks
	defer stdinR.Close()
	defer stdinW.Close()
	defer stdoutR.Close()
	defer stdoutW.Close()

	// Create CLISession
	session, err := NewCLISession(stdinW, stdoutR, nil)
	if err != nil {
		t.Fatalf("Failed to create CLI session: %v", err)
	}
	defer session.Close()

	// Load config
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Run CLI in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		term := ui.NewConsole(stdinR, stdoutW)
		errChan <- Run(ctx, cfg, "test-version", term)
	}()

	// Test scenario: Send /version command and verify output
	// Using ExpectString instead of time.Sleep
	if err := session.ExpectPrompt(5 * time.Second); err != nil {
		t.Fatalf("Failed to wait for initial prompt: %v", err)
	}

	// Send /version command
	if err := session.SendLine("/version"); err != nil {
		t.Fatalf("Failed to send /version: %v", err)
	}

	// Wait for version output
	if err := session.ExpectString("Koopa v", 3*time.Second); err != nil {
		t.Fatalf("Failed to get version output: %v", err)
	}

	// Wait for next prompt
	if err := session.ExpectPrompt(3 * time.Second); err != nil {
		t.Fatalf("Failed to wait for prompt after /version: %v", err)
	}

	// Send /exit to gracefully exit
	if err := session.SendLine("/exit"); err != nil {
		t.Fatalf("Failed to send /exit: %v", err)
	}

	// Wait for CLI to exit
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("CLI exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for CLI to exit")
	}

	// Verify output contains expected strings
	output := session.GetOutput()
	expectedStrings := []string{
		"Koopa v",
		"test-version",
	}

	for _, expected := range expectedStrings {
		if !containsString(output, expected) {
			t.Errorf("Expected output to contain %q\nGot:\n%s", expected, output)
		}
	}
}

// TestCLISession_HelpCommand demonstrates testing /help command
func TestCLISession_HelpCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// This test requires GEMINI_API_KEY to be set
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set, skipping E2E test")
	}

	// Create pipes
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	// IMPORTANT: Ensure all pipe ends are closed to prevent resource leaks
	defer stdinR.Close()
	defer stdinW.Close()
	defer stdoutR.Close()
	defer stdoutW.Close()

	session, err := NewCLISession(stdinW, stdoutR, nil)
	if err != nil {
		t.Fatalf("Failed to create CLI session: %v", err)
	}
	defer session.Close()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		term := ui.NewConsole(stdinR, stdoutW)
		errChan <- Run(ctx, cfg, "1.0.0", term)
	}()

	// Wait for initial prompt
	if err := session.ExpectPrompt(5 * time.Second); err != nil {
		t.Fatalf("Failed to wait for prompt: %v", err)
	}

	// Send /help
	if err := session.SendLine("/help"); err != nil {
		t.Fatalf("Failed to send /help: %v", err)
	}

	// Expect help output
	if err := session.ExpectString("Available Commands", 3*time.Second); err != nil {
		t.Fatalf("Failed to find 'Available Commands': %v", err)
	}

	// Verify RAG commands are documented
	if err := session.ExpectString("/rag", 1*time.Second); err != nil {
		t.Fatalf("Failed to find '/rag' in help: %v", err)
	}

	// Send /exit
	if err := session.SendLine("/exit"); err != nil {
		t.Fatalf("Failed to send /exit: %v", err)
	}

	// Wait for CLI to exit and check for errors
	select {
	case err := <-errChan:
		if err != nil && err != context.DeadlineExceeded {
			t.Fatalf("CLI exited with unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for CLI to exit")
	}
}
