// Package mcp provides Model Context Protocol (MCP) integration for the agent system.
//
// MCP enables AI agents to connect to external tools and services (like "plugins for AI agents").
// This package provides Server type for managing multiple MCP server connections with:
//   - Graceful degradation: Optional, doesn't block Agent if servers fail
//   - State tracking: Per-server connection states (Disconnected → Connecting → Connected/Failed)
//   - Thread safety: sync.RWMutex for concurrent access
//   - Explicit configuration: Loaded from config.yaml via LoadConfigs()
//
// Component files: server.go (connection management), state.go (state tracking), config.go (configuration).
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
	// Key: server name (e.g., "github", "filesystem")
	// Value: connection state (stored by value to prevent external mutation)
	states map[string]State

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

	// Validate server names and check for duplicates
	nameSet := make(map[string]struct{})
	for i, cfg := range configs {
		// Validate that server name is non-empty
		if cfg.Name == "" {
			return nil, fmt.Errorf("MCP server name cannot be empty (config index %d)", i)
		}
		// Check for duplicate names
		if _, exists := nameSet[cfg.Name]; exists {
			return nil, fmt.Errorf("duplicate MCP server name: %s (config index %d)", cfg.Name, i)
		}
		nameSet[cfg.Name] = struct{}{}
	}

	// Initialize state map (storing values instead of pointers)
	states := make(map[string]State)
	for _, cfg := range configs {
		states[cfg.Name] = State{
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
		for name, state := range states {
			state.Status = Failed
			state.LastError = err
			state.FailureCount++
			states[name] = state // Must reassign when using value map
		}
		slog.Error("failed to create MCP host",
			"error", err,
			"server_count", len(configs))
		return nil, fmt.Errorf("failed to create MCP host: %w", err)
	}

	// Optimistically mark all servers as connected
	// (MCPHost doesn't provide per-server status, so we track optimistically)
	for name, state := range states {
		state.Status = Connected
		state.SuccessCount++
		states[name] = state // Must reassign when using value map
	}

	slog.Info("MCP host created successfully", "server_count", len(configs))

	return &Server{
		host:   host,
		states: states,
	}, nil
}

// Tools retrieves all tools from all connected MCP servers.
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
func (s *Server) Tools(ctx context.Context, g *genkit.Genkit) ([]ai.Tool, error) {
	tools, err := s.host.GetActiveTools(ctx, g)
	if err != nil {
		// Mark all servers as failed (we don't know which one failed)
		s.mu.Lock()
		for name, state := range s.states {
			state.Status = Failed
			state.LastError = err
			state.FailureCount++
			state.LastAttempt = time.Now()
			s.states[name] = state // Must reassign when using value map
		}
		s.mu.Unlock()

		slog.Error("failed to get MCP tools", "error", err)
		return nil, fmt.Errorf("failed to get MCP tools: %w", err)
	}

	// Success: update all server states
	s.mu.Lock()
	for name, state := range s.states {
		state.Status = Connected
		state.LastError = nil
		state.SuccessCount++
		state.LastAttempt = time.Now()
		s.states[name] = state // Must reassign when using value map
	}
	s.mu.Unlock()

	slog.Info("retrieved MCP tools successfully", "tool_count", len(tools))
	return tools, nil
}

// State returns the connection state of a specific MCP server.
//
// Parameters:
//   - name: Name of the MCP server (e.g., "github", "filesystem")
//
// Returns:
//   - State: Copy of the server's state
//   - bool: true if server exists, false otherwise
//
// Note: Returns a copy of the state (map access returns a copy for value types).
func (s *Server) State(name string) (State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.states[name]
	if !exists {
		return State{}, false
	}

	// Map access returns a copy when value is stored by value
	return state, true
}

// States returns the connection states of all MCP servers.
//
// Returns:
//   - map[string]State: Map of server name to state (copies)
//
// Note: Returns copies of states (map iteration returns copies for value types).
func (s *Server) States() map[string]State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a copy of the states map
	result := make(map[string]State, len(s.states))
	for name, state := range s.states {
		result[name] = state // Iteration already returns a copy for value types
	}

	return result
}

// ServerNames returns the names of all configured MCP servers.
//
// This is useful for iteration or validation purposes.
func (s *Server) ServerNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.states))
	for name := range s.states {
		names = append(names, name)
	}

	return names
}

// ConnectedCount returns the number of currently connected MCP servers.
func (s *Server) ConnectedCount() int {
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
