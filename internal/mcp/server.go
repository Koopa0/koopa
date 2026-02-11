package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/koopa0/koopa/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP SDK server and Koopa's tool handlers.
// It exposes Koopa's tools via the Model Context Protocol.
type Server struct {
	mcpServer *mcp.Server
	logger    *slog.Logger
	file      *tools.File
	system    *tools.System
	network   *tools.Network
	knowledge *tools.Knowledge // nil when knowledge search is unavailable
}

// Config holds MCP server configuration.
type Config struct {
	Name      string
	Version   string
	Logger    *slog.Logger // Optional: nil uses slog.Default()
	File      *tools.File
	System    *tools.System
	Network   *tools.Network
	Knowledge *tools.Knowledge // Optional: nil disables knowledge search tools
}

// NewServer creates a new MCP server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	// Validate required config
	if cfg.Name == "" {
		return nil, errors.New("server name is required")
	}
	if cfg.Version == "" {
		return nil, errors.New("server version is required")
	}
	if cfg.File == nil {
		return nil, errors.New("file tools is required")
	}
	if cfg.System == nil {
		return nil, errors.New("system tools is required")
	}
	if cfg.Network == nil {
		return nil, errors.New("network tools is required")
	}

	// Create MCP server (using official SDK)
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Version: cfg.Version,
	}, nil)

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		mcpServer: mcpServer,
		logger:    logger,
		file:      cfg.File,
		system:    cfg.System,
		network:   cfg.Network,
		knowledge: cfg.Knowledge,
	}

	// Register all tools
	if err := s.registerTools(); err != nil {
		return nil, fmt.Errorf("registering tools: %w", err)
	}

	return s, nil
}

// Run starts the MCP server on the given transport.
// This is a blocking call that handles all MCP protocol communication.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	if err := s.mcpServer.Run(ctx, transport); err != nil {
		return fmt.Errorf("running mcp server: %w", err)
	}
	return nil
}

// registerTools registers all Toolset tools to the MCP server.
func (s *Server) registerTools() error {
	if err := s.registerFile(); err != nil {
		return fmt.Errorf("register file tools: %w", err)
	}

	if err := s.registerSystem(); err != nil {
		return fmt.Errorf("register system tools: %w", err)
	}

	if err := s.registerNetwork(); err != nil {
		return fmt.Errorf("register network tools: %w", err)
	}

	// Knowledge tools are optional (require DB + embedder)
	if s.knowledge != nil {
		if err := s.registerKnowledge(); err != nil {
			return fmt.Errorf("register knowledge tools: %w", err)
		}
	}

	return nil
}
