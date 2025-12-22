package mcp

import (
	"context"
	"fmt"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP SDK server and Koopa's tool handlers.
// It exposes Koopa's tools via the Model Context Protocol.
type Server struct {
	mcpServer    *mcp.Server
	fileTools    *tools.FileTools
	systemTools  *tools.SystemTools
	networkTools *tools.NetworkTools
	name         string
	version      string
}

// Config holds MCP server configuration.
type Config struct {
	Name         string
	Version      string
	FileTools    *tools.FileTools
	SystemTools  *tools.SystemTools
	NetworkTools *tools.NetworkTools
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
	if cfg.FileTools == nil {
		return nil, fmt.Errorf("file tools is required")
	}
	if cfg.SystemTools == nil {
		return nil, fmt.Errorf("system tools is required")
	}
	if cfg.NetworkTools == nil {
		return nil, fmt.Errorf("network tools is required")
	}

	// Create MCP server (using official SDK)
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Version: cfg.Version,
	}, nil)

	s := &Server{
		mcpServer:    mcpServer,
		fileTools:    cfg.FileTools,
		systemTools:  cfg.SystemTools,
		networkTools: cfg.NetworkTools,
		name:         cfg.Name,
		version:      cfg.Version,
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
