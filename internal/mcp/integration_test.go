//go:build integration
// +build integration

package mcp

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/stretchr/testify/require"
)

// createIntegrationTestConfig creates a complete Config for integration tests.
func createIntegrationTestConfig(t *testing.T, name string) Config {
	t.Helper()

	// Resolve symlinks in temp dir (macOS /var -> /private/var)
	tmpDir := t.TempDir()
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	pathVal, err := security.NewPath([]string{realTmpDir})
	require.NoError(t, err)

	fileToolset, err := tools.NewFileToolset(pathVal, slog.Default())
	require.NoError(t, err)

	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	systemToolset, err := tools.NewSystemToolset(cmdVal, envVal, slog.Default())
	require.NoError(t, err)

	networkToolset, err := tools.NewNetworkToolset(
		"http://localhost:8080", // test SearXNG URL
		2,                       // parallelism
		100*time.Millisecond,    // delay
		30*time.Second,          // timeout
		slog.Default(),
	)
	require.NoError(t, err)

	return Config{
		Name:           name,
		Version:        "1.0.0",
		FileToolset:    fileToolset,
		SystemToolset:  systemToolset,
		NetworkToolset: networkToolset,
	}
}

// TestServer_ConcurrentCreation tests that multiple servers can be created
// concurrently without race conditions.
//
// Run with: go test -race ./internal/mcp/...
func TestServer_ConcurrentCreation(t *testing.T) {
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	servers := make(chan *Server, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cfg := createIntegrationTestConfig(t, "race-test-server")

			server, err := NewServer(cfg)
			if err != nil {
				errors <- err
				return
			}
			servers <- server
		}(i)
	}

	wg.Wait()
	close(errors)
	close(servers)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent server creation error: %v", err)
	}

	// Count successful creations
	var count int
	for range servers {
		count++
	}

	if count != numGoroutines {
		t.Errorf("created %d servers, want %d", count, numGoroutines)
	}

	t.Logf("Successfully created %d servers concurrently", count)
}

// TestServer_ConcurrentToolsetAccess tests that the server's toolset
// can be accessed concurrently without race conditions.
func TestServer_ConcurrentToolsetAccess(t *testing.T) {
	// Resolve symlinks in temp dir (macOS /var -> /private/var)
	tmpDir := t.TempDir()
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	// Create a test file
	testFile := realTmpDir + "/test.txt"
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	cfg := createIntegrationTestConfig(t, "concurrent-access-test")
	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Access toolset concurrently
	const numGoroutines = 20
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Access toolset fields (read-only)
			_ = server.fileToolset
			_ = server.systemToolset
			_ = server.networkToolset
			_ = server.name
			_ = server.version
		}()
	}

	wg.Wait()
	t.Log("Concurrent toolset access completed without race")
}

// TestServer_RaceDetector is designed to trigger the Go race detector
// if there are any data races in Server field access.
//
// Run with: go test -race ./internal/mcp/...
func TestServer_RaceDetector(t *testing.T) {
	cfg := createIntegrationTestConfig(t, "race-detector-server")
	server, err := NewServer(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	const numOps = 50

	// Concurrent field access (read-only operations)
	for i := 0; i < numOps; i++ {
		wg.Add(5)

		// Read name
		go func() {
			defer wg.Done()
			_ = server.name
		}()

		// Read version
		go func() {
			defer wg.Done()
			_ = server.version
		}()

		// Read file toolset
		go func() {
			defer wg.Done()
			_ = server.fileToolset
		}()

		// Read system toolset
		go func() {
			defer wg.Done()
			_ = server.systemToolset
		}()

		// Read network toolset
		go func() {
			defer wg.Done()
			_ = server.networkToolset
		}()
	}

	wg.Wait()
	t.Log("Race detector test completed - Server fields are safe for concurrent read access")
}

// TestConfig_ConcurrentValidation tests that Config validation can run
// concurrently without issues.
func TestConfig_ConcurrentValidation(t *testing.T) {
	// Create valid toolsets for testing
	validCfg := createIntegrationTestConfig(t, "valid")

	configs := []Config{
		{Name: "server1", Version: "1.0.0", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset},
		{Name: "server2", Version: "2.0.0", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset},
		{Name: "", Version: "1.0.0", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset},   // Invalid: no name
		{Name: "server3", Version: "", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset}, // Invalid: no version
		{Name: "server4", Version: "1.0.0", FileToolset: nil, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset},             // Invalid: no file toolset
		{Name: "server5", Version: "1.0.0", FileToolset: validCfg.FileToolset, SystemToolset: nil, NetworkToolset: validCfg.NetworkToolset},               // Invalid: no system toolset
		{Name: "server6", Version: "1.0.0", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: nil},                // Invalid: no network toolset
		{Name: "server7", Version: "3.0.0", FileToolset: validCfg.FileToolset, SystemToolset: validCfg.SystemToolset, NetworkToolset: validCfg.NetworkToolset},
	}

	var wg sync.WaitGroup

	for _, cfg := range configs {
		wg.Add(1)
		go func(c Config) {
			defer wg.Done()
			// Attempt to create server (validates config)
			_, _ = NewServer(c)
		}(cfg)
	}

	wg.Wait()
	t.Log("Concurrent config validation completed without race")
}
