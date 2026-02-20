package mcp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"

	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/tools"
)

// mcpTestRetriever implements ai.Retriever for MCP protocol tests.
// Returns a single mock document so tests can verify result structure.
type mcpTestRetriever struct{}

func (*mcpTestRetriever) Name() string { return "mock-retriever" }
func (*mcpTestRetriever) Retrieve(_ context.Context, _ *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
	return &ai.RetrieverResponse{
		Documents: []*ai.Document{
			ai.DocumentFromText("mock result for protocol test", nil),
		},
	}, nil
}
func (*mcpTestRetriever) Register(_ api.Registry) {}

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
		t.Fatalf("resolving temp dir symlinks: %v", err)
	}
	return &testHelper{
		t:       t,
		tempDir: realTempDir,
	}
}

func (h *testHelper) createFile() *tools.File {
	h.t.Helper()
	pathVal, err := security.NewPath([]string{h.tempDir}, nil)
	if err != nil {
		h.t.Fatalf("creating path validator: %v", err)
	}

	ft, err := tools.NewFile(pathVal, slog.Default())
	if err != nil {
		h.t.Fatalf("creating file tools: %v", err)
	}
	return ft
}

func (h *testHelper) createSystem() *tools.System {
	h.t.Helper()
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()

	st, err := tools.NewSystem(cmdVal, envVal, slog.Default())
	if err != nil {
		h.t.Fatalf("creating system tools: %v", err)
	}
	return st
}

func (h *testHelper) createNetwork() *tools.Network {
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
	nt, err := tools.NewNetwork(
		tools.NetConfig{
			SearchBaseURL:    mockServer.URL,
			FetchParallelism: 2,
			FetchDelay:       100 * time.Millisecond,
			FetchTimeout:     30 * time.Second,
		},
		slog.Default(),
	)
	if err != nil {
		h.t.Fatalf("creating network tools: %v", err)
	}
	return nt
}

func (h *testHelper) createKnowledge() *tools.Knowledge {
	h.t.Helper()
	kt, err := tools.NewKnowledge(&mcpTestRetriever{}, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		h.t.Fatalf("creating knowledge tools: %v", err)
	}
	return kt
}

func (h *testHelper) createValidConfig() Config {
	h.t.Helper()
	return Config{
		Name:    "test-server",
		Version: "1.0.0",
		File:    h.createFile(),
		System:  h.createSystem(),
		Network: h.createNetwork(),
	}
}

func (h *testHelper) createConfigWithKnowledge() Config {
	h.t.Helper()
	cfg := h.createValidConfig()
	cfg.Knowledge = h.createKnowledge()
	return cfg
}

// TestNewServer_Success tests successful server creation with all tools.
func TestNewServer_Success(t *testing.T) {
	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}

	if server.mcpServer == nil {
		t.Error("server.mcpServer is nil")
	}

	if server.file == nil {
		t.Error("server.file is nil")
	}

	if server.system == nil {
		t.Error("server.system is nil")
	}

	if server.network == nil {
		t.Error("server.network is nil")
	}
}

// TestNewServer_ValidationErrors tests config validation.
func TestNewServer_ValidationErrors(t *testing.T) {
	h := newTestHelper(t)
	validFile := h.createFile()
	validSystem := h.createSystem()
	validNetwork := h.createNetwork()

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "missing name",
			config: Config{
				Version: "1.0.0",
				File:    validFile,
				System:  validSystem,
				Network: validNetwork,
			},
			wantErr: "server name is required",
		},
		{
			name: "missing version",
			config: Config{
				Name:    "test",
				File:    validFile,
				System:  validSystem,
				Network: validNetwork,
			},
			wantErr: "server version is required",
		},
		{
			name: "missing file tools",
			config: Config{
				Name:    "test",
				Version: "1.0.0",
				System:  validSystem,
				Network: validNetwork,
			},
			wantErr: "file tools is required",
		},
		{
			name: "missing system tools",
			config: Config{
				Name:    "test",
				Version: "1.0.0",
				File:    validFile,
				Network: validNetwork,
			},
			wantErr: "system tools is required",
		},
		{
			name: "missing network tools",
			config: Config{
				Name:    "test",
				Version: "1.0.0",
				File:    validFile,
				System:  validSystem,
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
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewServer error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
