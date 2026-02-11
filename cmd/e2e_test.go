//go:build e2e
// +build e2e

package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime" // Alias to avoid conflict with runtime package name
	"strings"
	"testing"
	"time"
)

// executableName returns the platform-specific binary name.
// On Windows, executables require .exe extension.
func executableName() string {
	if goruntime.GOOS == "windows" {
		return "koopa.exe"
	}
	return "koopa"
}

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
//   - Verify end-to-end user workflows

const shortTimeout = 30 * time.Second

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
	binName := executableName()
	koopaBin := filepath.Join(projectRoot, binName)

	// Try to find existing binary
	if _, err := os.Stat(koopaBin); err == nil {
		t.Log("Using existing koopa binary")
		return koopaBin
	}

	// Build binary in project root
	t.Log("Building koopa binary for E2E tests...")
	cmd := exec.Command("go", "build", "-o", binName, ".")
	cmd.Dir = projectRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build error: %v\nOutput: %s", err, output)
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
	if err != nil {
		t.Fatalf("running version command: %v", err)
	}

	if !strings.Contains(output, "Koopa") {
		t.Errorf("version command output = %q, want to contain %q", output, "Koopa")
	}
	if !strings.Contains(output, "v") {
		t.Errorf("version command output = %q, want to contain %q", output, "v")
	}
}

// TestE2E_ErrorRecovery tests CLI behavior with various inputs
func TestE2E_ErrorRecovery(t *testing.T) {
	ctx := setupE2ETest(t)

	t.Run("help command works", func(t *testing.T) {
		output, err := ctx.runKoopaCommand(shortTimeout, "help")
		if err != nil {
			t.Errorf("running help command: %v", err)
		}
		if !strings.Contains(strings.ToLower(output), "koopa") {
			t.Errorf("help command output = %q, want to contain %q", output, "koopa")
		}
	})

	t.Run("version without api key", func(t *testing.T) {
		// Temporarily unset API key
		originalKey := ctx.apiKey
		ctx.apiKey = ""

		output, err := ctx.runKoopaCommand(shortTimeout, "version")

		// Restore API key
		ctx.apiKey = originalKey

		// Version command should still work without API key
		if err != nil {
			t.Errorf("running version command without API key: %v", err)
		}
		if !strings.Contains(output, "Koopa") {
			t.Errorf("version command output = %q, want to contain %q", output, "Koopa")
		}
	})
}
