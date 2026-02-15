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
)

// createIntegrationTestConfig creates a complete Config for integration tests.
func createIntegrationTestConfig(t *testing.T, name string) Config {
	t.Helper()

	// Resolve symlinks in temp dir (macOS /var -> /private/var)
	tmpDir := t.TempDir()
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) unexpected error: %v", tmpDir, err)
	}

	pathVal, err := security.NewPath([]string{realTmpDir}, nil)
	if err != nil {
		t.Fatalf("security.NewPath(%q) unexpected error: %v", realTmpDir, err)
	}

	file, err := tools.NewFile(pathVal, slog.Default())
	if err != nil {
		t.Fatalf("tools.NewFile() unexpected error: %v", err)
	}

	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	system, err := tools.NewSystem(cmdVal, envVal, slog.Default())
	if err != nil {
		t.Fatalf("tools.NewSystem() unexpected error: %v", err)
	}

	networkCfg := tools.NetConfig{
		SearchBaseURL:    "http://localhost:8080",
		FetchParallelism: 2,
		FetchDelay:       100 * time.Millisecond,
		FetchTimeout:     30 * time.Second,
	}
	network, err := tools.NewNetwork(networkCfg, slog.Default())
	if err != nil {
		t.Fatalf("tools.NewNetwork() unexpected error: %v", err)
	}

	return Config{
		Name:    name,
		Version: "1.0.0",
		File:    file,
		System:  system,
		Network: network,
	}
}

// TestServer_ConcurrentCreation tests that multiple servers can be created
// concurrently without race conditions.
//
// Run with: go test -race ./internal/mcp/...
func TestServer_ConcurrentCreation(t *testing.T) {
	const numGoroutines = 10

	// Pre-create configs outside goroutines — createIntegrationTestConfig
	// calls t.Fatalf which is undefined behavior from goroutines.
	configs := make([]Config, numGoroutines)
	for i := range configs {
		configs[i] = createIntegrationTestConfig(t, "race-test-server")
	}

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	servers := make(chan *Server, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(cfg Config) {
			defer wg.Done()
			server, err := NewServer(cfg)
			if err != nil {
				errors <- err
				return
			}
			servers <- server
		}(configs[i])
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
		t.Errorf("NewServer() created %d servers, want %d", count, numGoroutines)
	}

	t.Logf("Successfully created %d servers concurrently", count)
}

// TestServer_ConcurrentToolsetAccess tests that the server's toolset
// can be accessed concurrently without race conditions.
func TestServer_ConcurrentToolsetAccess(t *testing.T) {
	// Resolve symlinks in temp dir (macOS /var -> /private/var)
	tmpDir := t.TempDir()
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) unexpected error: %v", tmpDir, err)
	}

	// Create a test file
	testFile := realTmpDir + "/test.txt"
	err = os.WriteFile(testFile, []byte("test content"), 0600)
	if err != nil {
		t.Fatalf("WriteFile(%q) unexpected error: %v", testFile, err)
	}

	cfg := createIntegrationTestConfig(t, "concurrent-access-test")
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() unexpected error: %v", err)
	}

	// Access toolset concurrently
	const numGoroutines = 20
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Access toolset fields (read-only)
			_ = server.file
			_ = server.system
			_ = server.network
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
	if err != nil {
		t.Fatalf("NewServer() unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	const numOps = 50

	// Concurrent field access (read-only operations)
	for i := 0; i < numOps; i++ {
		wg.Add(3)

		// Read file tools
		go func() {
			defer wg.Done()
			_ = server.file
		}()

		// Read system tools
		go func() {
			defer wg.Done()
			_ = server.system
		}()

		// Read network tools
		go func() {
			defer wg.Done()
			_ = server.network
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
		{Name: "server1", Version: "1.0.0", File: validCfg.File, System: validCfg.System, Network: validCfg.Network},
		{Name: "server2", Version: "2.0.0", File: validCfg.File, System: validCfg.System, Network: validCfg.Network},
		{Name: "", Version: "1.0.0", File: validCfg.File, System: validCfg.System, Network: validCfg.Network},   // Invalid: no name
		{Name: "server3", Version: "", File: validCfg.File, System: validCfg.System, Network: validCfg.Network}, // Invalid: no version
		{Name: "server4", Version: "1.0.0", File: nil, System: validCfg.System, Network: validCfg.Network},      // Invalid: no file tools
		{Name: "server5", Version: "1.0.0", File: validCfg.File, System: nil, Network: validCfg.Network},        // Invalid: no system tools
		{Name: "server6", Version: "1.0.0", File: validCfg.File, System: validCfg.System, Network: nil},         // Invalid: no network tools
		{Name: "server7", Version: "3.0.0", File: validCfg.File, System: validCfg.System, Network: validCfg.Network},
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
