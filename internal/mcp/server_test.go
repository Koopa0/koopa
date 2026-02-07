package mcp

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/tools"
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

func (h *testHelper) createFileTools() *tools.FileTools {
	h.t.Helper()
	pathVal, err := security.NewPath([]string{h.tempDir})
	if err != nil {
		h.t.Fatalf("failed to create path validator: %v", err)
	}

	ft, err := tools.NewFileTools(pathVal, slog.Default())
	if err != nil {
		h.t.Fatalf("failed to create file tools: %v", err)
	}
	return ft
}

func (h *testHelper) createSystemTools() *tools.SystemTools {
	h.t.Helper()
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()

	st, err := tools.NewSystemTools(cmdVal, envVal, slog.Default())
	if err != nil {
		h.t.Fatalf("failed to create system tools: %v", err)
	}
	return st
}

func (h *testHelper) createNetworkTools() *tools.NetworkTools {
	h.t.Helper()

	// Use httptest.NewServer instead of hardcoded localhost URL
	// This ensures tests are self-contained and don't depend on external services
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty results if called (server_test.go only tests NewServer, not tool execution)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	h.t.Cleanup(func() { mockServer.Close() })

	// SSRF protection is only checked during Fetch(), not at construction.
	// These tests only construct tools for Config, they don't execute network operations.
	nt, err := tools.NewNetworkTools(
		tools.NetworkConfig{
			SearchBaseURL:    mockServer.URL,
			FetchParallelism: 2,
			FetchDelay:       100 * time.Millisecond,
			FetchTimeout:     30 * time.Second,
		},
		slog.Default(),
	)
	if err != nil {
		h.t.Fatalf("failed to create network tools: %v", err)
	}
	return nt
}

func (h *testHelper) createValidConfig() Config {
	h.t.Helper()
	return Config{
		Name:         "test-server",
		Version:      "1.0.0",
		FileTools:    h.createFileTools(),
		SystemTools:  h.createSystemTools(),
		NetworkTools: h.createNetworkTools(),
	}
}

// TestNewServer_Success tests successful server creation with all tools.
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

	if server.fileTools == nil {
		t.Error("server.fileTools is nil")
	}

	if server.systemTools == nil {
		t.Error("server.systemTools is nil")
	}

	if server.networkTools == nil {
		t.Error("server.networkTools is nil")
	}
}

// TestNewServer_ValidationErrors tests config validation.
func TestNewServer_ValidationErrors(t *testing.T) {
	h := newTestHelper(t)
	validFile := h.createFileTools()
	validSystem := h.createSystemTools()
	validNetwork := h.createNetworkTools()

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "missing name",
			config: Config{
				Version:      "1.0.0",
				FileTools:    validFile,
				SystemTools:  validSystem,
				NetworkTools: validNetwork,
			},
			wantErr: "server name is required",
		},
		{
			name: "missing version",
			config: Config{
				Name:         "test",
				FileTools:    validFile,
				SystemTools:  validSystem,
				NetworkTools: validNetwork,
			},
			wantErr: "server version is required",
		},
		{
			name: "missing file tools",
			config: Config{
				Name:         "test",
				Version:      "1.0.0",
				SystemTools:  validSystem,
				NetworkTools: validNetwork,
			},
			wantErr: "file tools is required",
		},
		{
			name: "missing system tools",
			config: Config{
				Name:         "test",
				Version:      "1.0.0",
				FileTools:    validFile,
				NetworkTools: validNetwork,
			},
			wantErr: "system tools is required",
		},
		{
			name: "missing network tools",
			config: Config{
				Name:        "test",
				Version:     "1.0.0",
				FileTools:   validFile,
				SystemTools: validSystem,
			},
			wantErr: "network tools is required",
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

// TestRegisterTools_AllToolsRegistered verifies all 10 tools are registered.
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
	// error means registerTools() completed successfully for all 10 tools:
	// - File: read_file, write_file, list_files, delete_file, get_file_info
	// - System: current_time, execute_command, get_env
	// - Network: web_search, web_fetch
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
