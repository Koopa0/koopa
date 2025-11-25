//go:build e2e
// +build e2e

package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// E2E tests validate complete user workflows against real infrastructure.
//
// Requirements:
//   - Real PostgreSQL database (DATABASE_URL must be set)
//   - Real Gemini API key (GEMINI_API_KEY must be set)
//   - Koopa binary built and available
//
// Run with:
//   go test -tags=e2e ./cmd -v
//
// These tests:
//   - Execute the actual Koopa CLI binary
//   - Test real API interactions with Gemini
//   - Validate database persistence
//   - Test MCP protocol integration
//   - Verify end-to-end user workflows

const (
	testTimeout        = 90 * time.Second
	shortTimeout       = 30 * time.Second
	defaultTestSession = "e2e-test-session"
)

// e2eTestContext holds test infrastructure
type e2eTestContext struct {
	t           *testing.T
	koopaBin    string
	workDir     string
	databaseURL string
	apiKey      string
}

// setupE2ETest prepares the E2E test environment
func setupE2ETest(t *testing.T) *e2eTestContext {
	t.Helper()

	// Check required environment variables
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set, skipping E2E test")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set, skipping E2E test")
	}

	// Find or build Koopa binary
	koopaBin := findOrBuildKoopa(t)

	// Create temporary working directory
	workDir := t.TempDir()

	return &e2eTestContext{
		t:           t,
		koopaBin:    koopaBin,
		workDir:     workDir,
		databaseURL: databaseURL,
		apiKey:      apiKey,
	}
}

// findOrBuildKoopa locates or builds the Koopa binary
func findOrBuildKoopa(t *testing.T) string {
	t.Helper()

	// Get project root (parent of cmd/)
	projectRoot, _ := filepath.Abs("..")
	koopaBin := filepath.Join(projectRoot, "koopa")

	// Try to find existing binary
	if _, err := os.Stat(koopaBin); err == nil {
		t.Log("Using existing koopa binary")
		return koopaBin
	}

	// Build binary in project root
	t.Log("Building koopa binary for E2E tests...")
	cmd := exec.Command("go", "build", "-o", "koopa", ".")
	cmd.Dir = projectRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build koopa: %v\nOutput: %s", err, output)
	}

	return koopaBin
}

// runKoopaCommand executes a Koopa CLI command and returns output
func (ctx *e2eTestContext) runKoopaCommand(timeout time.Duration, args ...string) (string, error) {
	ctx.t.Helper()

	cmdCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, ctx.koopaBin, args...)
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+ctx.databaseURL,
		"GEMINI_API_KEY="+ctx.apiKey,
	)
	cmd.Dir = ctx.workDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()

	if err != nil {
		ctx.t.Logf("Command failed: %v\nOutput: %s", err, output)
	}

	return output, err
}

// TestE2E_VersionCommand tests the version command
func TestE2E_VersionCommand(t *testing.T) {
	ctx := setupE2ETest(t)

	output, err := ctx.runKoopaCommand(shortTimeout, "version")
	require.NoError(t, err, "version command should succeed")

	assert.Contains(t, output, "Koopa", "version output should contain 'Koopa'")
	assert.Contains(t, output, "v0.", "version output should show version number")
}

// TestE2E_BasicChatWorkflow tests a complete chat interaction workflow
func TestE2E_BasicChatWorkflow(t *testing.T) {
	t.Skip("Interactive chat workflow requires stdin interaction - implement with expect-like tool")

	// This test would:
	// 1. Start Koopa in chat mode
	// 2. Send a simple question like "What is 2+2?"
	// 3. Verify response is received
	// 4. Test /exit command
	//
	// Implementation requires:
	// - PTY (pseudo-terminal) for interactive I/O
	// - Expect-like tool (e.g., github.com/Netflix/go-expect)
	// - Or restructure CLI to support non-interactive mode
}

// TestE2E_SessionManagement tests session creation and management
func TestE2E_SessionManagement(t *testing.T) {
	t.Skip("Session management requires CLI refactoring for non-interactive testing")

	// This test would validate:
	// - /session new "Test Session"
	// - /session list
	// - /session switch <id>
	// - Session persistence across restarts
}

// TestE2E_RAGWorkflow tests document indexing and retrieval
func TestE2E_RAGWorkflow(t *testing.T) {
	t.Skip("RAG workflow requires CLI refactoring for non-interactive testing")

	// This test would validate:
	// 1. Create test documents in temp directory
	// 2. /rag add <path>
	// 3. /rag list
	// 4. Query indexed content
	// 5. Verify RAG results in response
	// 6. /rag status
}

// TestE2E_MCPServer tests MCP server functionality
func TestE2E_MCPServer(t *testing.T) {
	ctx := setupE2ETest(t)

	// Start MCP server
	cmdCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, ctx.koopaBin, "mcp")
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+ctx.databaseURL,
		"GEMINI_API_KEY="+ctx.apiKey,
	)

	// Create stdin/stdout pipes for MCP communication
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	// Send MCP initialize request
	initRequest := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}` + "\n"
	_, err = stdin.Write([]byte(initRequest))
	require.NoError(t, err)

	// Read response with timeout
	responseChan := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := stdout.Read(buf)
		responseChan <- string(buf[:n])
	}()

	select {
	case response := <-responseChan:
		t.Logf("MCP initialize response: %s", response)
		assert.Contains(t, response, "result", "MCP response should contain result")
		assert.Contains(t, response, "serverInfo", "MCP response should contain serverInfo")
	case <-time.After(10 * time.Second):
		t.Fatal("MCP server did not respond within timeout")
	}

	// Cleanup
	stdin.Close()
	cmd.Process.Kill()
	cmd.Wait()
}

// TestE2E_MCPToolsAvailable tests that MCP exposes expected tools
func TestE2E_MCPToolsAvailable(t *testing.T) {
	ctx := setupE2ETest(t)

	cmdCtx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, ctx.koopaBin, "mcp")
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+ctx.databaseURL,
		"GEMINI_API_KEY="+ctx.apiKey,
	)

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Initialize MCP
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}` + "\n"
	_, err = stdin.Write([]byte(initReq))
	require.NoError(t, err)

	// Read initialize response first
	buf := make([]byte, 8192)
	n, err := stdout.Read(buf)
	require.NoError(t, err)
	initResponse := string(buf[:n])
	t.Logf("MCP initialize response: %s", initResponse)
	assert.Contains(t, initResponse, "result", "MCP initialize should return result")

	// Request tools list
	toolsReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"
	_, err = stdin.Write([]byte(toolsReq))
	require.NoError(t, err)

	// Read tools/list response
	n, err = stdout.Read(buf)
	require.NoError(t, err)
	toolsResponse := string(buf[:n])
	t.Logf("MCP tools/list response: %s", toolsResponse)

	// Verify expected tools are available
	assert.Contains(t, toolsResponse, "readFile", "MCP should expose readFile tool")
}

// TestE2E_DatabasePersistence tests that data persists across CLI restarts
func TestE2E_DatabasePersistence(t *testing.T) {
	t.Skip("Database persistence testing requires CLI refactoring for session creation via CLI")

	// This test would validate:
	// 1. Create session with specific title
	// 2. Exit CLI
	// 3. Restart CLI
	// 4. List sessions and verify created session exists
}

// TestE2E_ErrorRecovery tests CLI behavior with various inputs
func TestE2E_ErrorRecovery(t *testing.T) {
	ctx := setupE2ETest(t)

	t.Run("help command works", func(t *testing.T) {
		output, err := ctx.runKoopaCommand(shortTimeout, "help")
		assert.NoError(t, err, "help command should succeed")
		assert.Contains(t, strings.ToLower(output), "koopa", "help output should mention koopa")
	})

	t.Run("version without api key", func(t *testing.T) {
		// Temporarily unset API key
		originalKey := ctx.apiKey
		ctx.apiKey = ""

		output, err := ctx.runKoopaCommand(shortTimeout, "version")

		// Restore API key
		ctx.apiKey = originalKey

		// Version command should still work without API key
		assert.NoError(t, err, "version should work without API key")
		assert.Contains(t, output, "Koopa", "version output should show Koopa")
	})
}

// TestE2E_ConcurrentAccess tests that multiple CLI instances can coexist
func TestE2E_ConcurrentAccess(t *testing.T) {
	t.Skip("Concurrent access testing requires session isolation implementation")

	// This test would validate:
	// 1. Start two CLI instances
	// 2. Create different sessions in each
	// 3. Verify no data corruption
	// 4. Verify proper session isolation
}

// TestE2E_ToolExecution tests that agent tools execute correctly
func TestE2E_ToolExecution(t *testing.T) {
	t.Skip("Tool execution testing requires interactive CLI or agent API endpoint")

	// This test would validate:
	// 1. Ask agent to read a file
	// 2. Verify tool call happens
	// 3. Verify correct file content returned
	// 4. Test other tools (system, network, knowledge)
}

// TestE2E_IntegrationTestHelper verifies E2E test infrastructure
func TestE2E_IntegrationTestHelper(t *testing.T) {
	ctx := setupE2ETest(t)

	// Verify binary exists
	assert.FileExists(t, ctx.koopaBin, "Koopa binary should exist")

	// Verify working directory
	assert.DirExists(t, ctx.workDir, "Working directory should exist")

	// Verify environment
	assert.NotEmpty(t, ctx.databaseURL, "DATABASE_URL should be set")
	assert.NotEmpty(t, ctx.apiKey, "GEMINI_API_KEY should be set")

	t.Logf("E2E test infrastructure:")
	t.Logf("  Binary: %s", ctx.koopaBin)
	t.Logf("  WorkDir: %s", ctx.workDir)
	t.Logf("  Database: %s", ctx.databaseURL)
}
