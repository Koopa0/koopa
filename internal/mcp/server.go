package mcp

import (
	"context"
	"fmt"

	"github.com/koopa0/koopa-cli/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP SDK server and Koopa's Toolsets.
// It exposes Koopa's tools via the Model Context Protocol.
type Server struct {
	mcpServer      *mcp.Server
	fileToolset    *tools.FileToolset
	systemToolset  *tools.SystemToolset
	networkToolset *tools.NetworkToolset
	name           string
	version        string
}

// Config holds MCP server configuration.
type Config struct {
	Name           string
	Version        string
	FileToolset    *tools.FileToolset
	SystemToolset  *tools.SystemToolset
	NetworkToolset *tools.NetworkToolset
}

// NewServer creates a new MCP server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	// Validate required config
	if cfg.Name == "" {
		return nil, fmt.Errorf("server name is required")
	}
	if cfg.Version == "" {
		return nil, fmt.Errorf("server version is required")
	}
	if cfg.FileToolset == nil {
		return nil, fmt.Errorf("file toolset is required")
	}
	if cfg.SystemToolset == nil {
		return nil, fmt.Errorf("system toolset is required")
	}
	if cfg.NetworkToolset == nil {
		return nil, fmt.Errorf("network toolset is required")
	}

	// Create MCP server (using official SDK)
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Version: cfg.Version,
	}, nil)

	s := &Server{
		mcpServer:      mcpServer,
		fileToolset:    cfg.FileToolset,
		systemToolset:  cfg.SystemToolset,
		networkToolset: cfg.NetworkToolset,
		name:           cfg.Name,
		version:        cfg.Version,
	}

	// Register all tools
	if err := s.registerTools(); err != nil {
		return nil, fmt.Errorf("failed to register tools: %w", err)
	}

	return s, nil
}

// Run starts the MCP server on the given transport.
// This is a blocking call that handles all MCP protocol communication.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	if err := s.mcpServer.Run(ctx, transport); err != nil {
		return fmt.Errorf("MCP server run failed: %w", err)
	}
	return nil
}

// registerTools registers all Toolset tools to the MCP server.
func (s *Server) registerTools() error {
	if err := s.registerFileTools(); err != nil {
		return fmt.Errorf("register file tools: %w", err)
	}

	if err := s.registerSystemTools(); err != nil {
		return fmt.Errorf("register system tools: %w", err)
	}

	if err := s.registerNetworkTools(); err != nil {
		return fmt.Errorf("register network tools: %w", err)
	}

	return nil
}
