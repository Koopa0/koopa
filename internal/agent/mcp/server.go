package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/mcp"
)

// Server manages connections to multiple MCP servers and provides
// a unified interface for retrieving tools and monitoring connection states.
//
// This type follows Go naming conventions (like http.Server, sql.DB)
// where the package provides context and the type name is concise.
type Server struct {
	// host is the Genkit MCPHost that manages actual MCP server connections.
	host *mcp.MCPHost

	// states tracks the state of each MCP server connection.
	// Key: server name (e.g., "github", "notion")
	// Value: connection state
	states map[string]*State

	// mu protects concurrent access to states map.
	mu sync.RWMutex
}

// Config represents configuration for a single MCP server.
type Config struct {
	Name          string
	ClientOptions mcp.MCPClientOptions
}

// New creates a new MCP Server instance with the provided configurations.
//
// Parameters:
//   - ctx: Context for the initialization (passed to Genkit)
//   - g: Genkit instance (required for MCPHost creation)
//   - configs: Slice of MCP server configurations to connect to
//
// Returns:
//   - *Server: Successfully created server instance
//   - error: If MCPHost creation fails
//
// The function will attempt to connect to all configured MCP servers.
// If some servers fail to connect, they will be marked as Failed in state,
// but the Server instance will still be created successfully (graceful degradation).
func New(ctx context.Context, g *genkit.Genkit, configs []Config) (*Server, error) {
	// Convert Config slice to MCPServerConfig slice for Genkit
	serverConfigs := make([]mcp.MCPServerConfig, len(configs))
	for i, cfg := range configs {
		serverConfigs[i] = mcp.MCPServerConfig{
			Name:   cfg.Name,
			Config: cfg.ClientOptions,
		}
	}

	// Initialize state map
	states := make(map[string]*State)
	for _, cfg := range configs {
		states[cfg.Name] = &State{
			Name:        cfg.Name,
			Status:      Connecting,
			LastAttempt: time.Now(),
		}
	}

	// Create MCPHost
	slog.Info("creating MCP host", "server_count", len(configs))
	host, err := mcp.NewMCPHost(g, mcp.MCPHostOptions{
		Name:       "koopa-mcp",
		Version:    "1.0.0",
		MCPServers: serverConfigs,
	})

	if err != nil {
		// Mark all servers as failed
		for _, state := range states {
			state.Status = Failed
			state.LastError = err
			state.FailureCount++
		}
		slog.Error("failed to create MCP host",
			"error", err,
			"server_count", len(configs))
		return nil, fmt.Errorf("failed to create MCP host: %w", err)
	}

	// Optimistically mark all servers as connected
	// (MCPHost doesn't provide per-server status, so we track optimistically)
	for _, state := range states {
		state.Status = Connected
		state.SuccessCount++
	}

	slog.Info("MCP host created successfully", "server_count", len(configs))

	return &Server{
		host:   host,
		states: states,
	}, nil
}

// GetTools retrieves all tools from all connected MCP servers.
//
// This method aggregates tools from all MCP servers managed by the MCPHost.
// The tools are automatically converted to Genkit ai.Tool format and are
// ready to be used in Generate() calls.
//
// Parameters:
//   - ctx: Context for the operation
//   - g: Genkit instance (required by MCPHost.GetActiveTools)
//
// Returns:
//   - []ai.Tool: Slice of all available tools from all connected servers
//   - error: If tool retrieval fails
//
// Error Handling:
//   - If tool retrieval fails, all servers are marked as Failed
//   - The error is logged and returned to the caller
//   - Caller should handle gracefully (e.g., fall back to local tools only)
func (s *Server) GetTools(ctx context.Context, g *genkit.Genkit) ([]ai.Tool, error) {
	tools, err := s.host.GetActiveTools(ctx, g)
	if err != nil {
		// Mark all servers as failed (we don't know which one failed)
		s.mu.Lock()
		for _, state := range s.states {
			state.Status = Failed
			state.LastError = err
			state.FailureCount++
			state.LastAttempt = time.Now()
		}
		s.mu.Unlock()

		slog.Error("failed to get MCP tools", "error", err)
		return nil, fmt.Errorf("failed to get MCP tools: %w", err)
	}

	// Success: update all server states
	s.mu.Lock()
	for _, state := range s.states {
		state.Status = Connected
		state.LastError = nil
		state.SuccessCount++
		state.LastAttempt = time.Now()
	}
	s.mu.Unlock()

	slog.Info("retrieved MCP tools successfully", "tool_count", len(tools))
	return tools, nil
}

// GetState returns the connection state of a specific MCP server.
//
// Parameters:
//   - name: Name of the MCP server (e.g., "github", "notion")
//
// Returns:
//   - State: Copy of the server's state
//   - bool: true if server exists, false otherwise
//
// Note: Returns a copy of the state to prevent external modifications.
func (s *Server) GetState(name string) (State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.states[name]
	if !exists {
		return State{}, false
	}

	// Return a copy to prevent external modification
	return *state, true
}

// GetStates returns the connection states of all MCP servers.
//
// Returns:
//   - map[string]State: Map of server name to state (copies)
//
// Note: Returns copies of states to prevent external modifications.
func (s *Server) GetStates() map[string]State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a copy of the states map
	result := make(map[string]State, len(s.states))
	for name, state := range s.states {
		result[name] = *state // Copy the state
	}

	return result
}

// GetServerNames returns the names of all configured MCP servers.
//
// This is useful for iteration or validation purposes.
func (s *Server) GetServerNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.states))
	for name := range s.states {
		names = append(names, name)
	}

	return names
}

// GetConnectedCount returns the number of currently connected MCP servers.
func (s *Server) GetConnectedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, state := range s.states {
		if state.Status == Connected {
			count++
		}
	}

	return count
}
