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

	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/tools"
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

	fileTools, err := tools.NewFileTools(pathVal, slog.Default())
	require.NoError(t, err)

	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	systemTools, err := tools.NewSystemTools(cmdVal, envVal, slog.Default())
	require.NoError(t, err)

	networkCfg := tools.NetworkConfig{
		SearchBaseURL:    "http://localhost:8080",
		FetchParallelism: 2,
		FetchDelay:       100 * time.Millisecond,
		FetchTimeout:     30 * time.Second,
	}
	networkTools, err := tools.NewNetworkTools(networkCfg, slog.Default())
	require.NoError(t, err)

	return Config{
		Name:         name,
		Version:      "1.0.0",
		FileTools:    fileTools,
		SystemTools:  systemTools,
		NetworkTools: networkTools,
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
	err = os.WriteFile(testFile, []byte("test content"), 0600)
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
			_ = server.fileTools
			_ = server.systemTools
			_ = server.networkTools
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

		// Read file tools
		go func() {
			defer wg.Done()
			_ = server.fileTools
		}()

		// Read system tools
		go func() {
			defer wg.Done()
			_ = server.systemTools
		}()

		// Read network tools
		go func() {
			defer wg.Done()
			_ = server.networkTools
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
		{Name: "server1", Version: "1.0.0", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools},
		{Name: "server2", Version: "2.0.0", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools},
		{Name: "", Version: "1.0.0", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools},   // Invalid: no name
		{Name: "server3", Version: "", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools}, // Invalid: no version
		{Name: "server4", Version: "1.0.0", FileTools: nil, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools},           // Invalid: no file tools
		{Name: "server5", Version: "1.0.0", FileTools: validCfg.FileTools, SystemTools: nil, NetworkTools: validCfg.NetworkTools},             // Invalid: no system tools
		{Name: "server6", Version: "1.0.0", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: nil},              // Invalid: no network tools
		{Name: "server7", Version: "3.0.0", FileTools: validCfg.FileTools, SystemTools: validCfg.SystemTools, NetworkTools: validCfg.NetworkTools},
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
