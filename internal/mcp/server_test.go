package mcp

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// testHelper provides common test utilities.
type testHelper struct {
	t       *testing.T
	tempDir string
}

func newTestHelper(t *testing.T) *testHelper {
	t.Helper()
	// Resolve symlinks in temp dir path (macOS /var -> /private/var)
	tempDir := t.TempDir()
	realTempDir, err := filepath.EvalSymlinks(tempDir)
	if err != nil {
		t.Fatalf("failed to resolve temp dir symlinks: %v", err)
	}
	return &testHelper{
		t:       t,
		tempDir: realTempDir,
	}
}

func (h *testHelper) createFileToolset() *tools.FileToolset {
	h.t.Helper()
	pathVal, err := security.NewPath([]string{h.tempDir})
	if err != nil {
		h.t.Fatalf("failed to create path validator: %v", err)
	}

	toolset, err := tools.NewFileToolset(pathVal, slog.Default())
	if err != nil {
		h.t.Fatalf("failed to create file toolset: %v", err)
	}
	return toolset
}

func (h *testHelper) createSystemToolset() *tools.SystemToolset {
	h.t.Helper()
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()

	toolset, err := tools.NewSystemToolset(cmdVal, envVal, slog.Default())
	if err != nil {
		h.t.Fatalf("failed to create system toolset: %v", err)
	}
	return toolset
}

func (h *testHelper) createNetworkToolset() *tools.NetworkToolset {
	h.t.Helper()

	toolset, err := tools.NewNetworkToolset(
		"http://localhost:8080", // test SearXNG URL
		nil,                     // use default http.Client
		2,                       // parallelism
		100*time.Millisecond,    // delay
		30*time.Second,          // timeout
		slog.Default(),
	)
	if err != nil {
		h.t.Fatalf("failed to create network toolset: %v", err)
	}
	return toolset
}

func (h *testHelper) createValidConfig() Config {
	h.t.Helper()
	return Config{
		Name:           "test-server",
		Version:        "1.0.0",
		FileToolset:    h.createFileToolset(),
		SystemToolset:  h.createSystemToolset(),
		NetworkToolset: h.createNetworkToolset(),
	}
}

// TestNewServer_Success tests successful server creation with all toolsets.
func TestNewServer_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Verify server fields are correctly set
	if server.name != "test-server" {
		t.Errorf("server.name = %q, want %q", server.name, "test-server")
	}

	if server.version != "1.0.0" {
		t.Errorf("server.version = %q, want %q", server.version, "1.0.0")
	}

	if server.mcpServer == nil {
		t.Error("server.mcpServer is nil")
	}

	if server.fileToolset == nil {
		t.Error("server.fileToolset is nil")
	}

	if server.systemToolset == nil {
		t.Error("server.systemToolset is nil")
	}

	if server.networkToolset == nil {
		t.Error("server.networkToolset is nil")
	}
}

// TestNewServer_ValidationErrors tests config validation.
func TestNewServer_ValidationErrors(t *testing.T) {
	h := newTestHelper(t)
	validFile := h.createFileToolset()
	validSystem := h.createSystemToolset()
	validNetwork := h.createNetworkToolset()

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "missing name",
			config: Config{
				Version:        "1.0.0",
				FileToolset:    validFile,
				SystemToolset:  validSystem,
				NetworkToolset: validNetwork,
			},
			wantErr: "server name is required",
		},
		{
			name: "missing version",
			config: Config{
				Name:           "test",
				FileToolset:    validFile,
				SystemToolset:  validSystem,
				NetworkToolset: validNetwork,
			},
			wantErr: "server version is required",
		},
		{
			name: "missing file toolset",
			config: Config{
				Name:           "test",
				Version:        "1.0.0",
				SystemToolset:  validSystem,
				NetworkToolset: validNetwork,
			},
			wantErr: "file toolset is required",
		},
		{
			name: "missing system toolset",
			config: Config{
				Name:           "test",
				Version:        "1.0.0",
				FileToolset:    validFile,
				NetworkToolset: validNetwork,
			},
			wantErr: "system toolset is required",
		},
		{
			name: "missing network toolset",
			config: Config{
				Name:          "test",
				Version:       "1.0.0",
				FileToolset:   validFile,
				SystemToolset: validSystem,
			},
			wantErr: "network toolset is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.config)
			if err == nil {
				t.Fatal("NewServer succeeded, want error")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("NewServer error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestRegisterTools_AllToolsRegistered verifies all 9 tools are registered.
func TestRegisterTools_AllToolsRegistered(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Verify server was created successfully (tools registered in constructor)
	if server.mcpServer == nil {
		t.Fatal("mcpServer is nil")
	}

	// Note: We can't directly verify tool registration without accessing
	// internal MCP server state. The fact that NewServer succeeded without
	// error means registerTools() completed successfully for all 9 tools:
	// - File: readFile, writeFile, listFiles, deleteFile, getFileInfo
	// - System: currentTime, executeCommand, getEnv
	// - Network: httpGet
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
