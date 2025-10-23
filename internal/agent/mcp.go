package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/mcp"
)

// MCPManager manages MCP client connections
type MCPManager struct {
	host *mcp.MCPHost
}

// NewMCPManager creates a new MCP manager (optionally configure MCP servers)
func NewMCPManager(ctx context.Context, g *genkit.Genkit, serverConfigs []mcp.MCPServerConfig) (*MCPManager, error) {
	// If no configuration provided, use empty configuration (allows dynamic addition later)
	if serverConfigs == nil {
		serverConfigs = make([]mcp.MCPServerConfig, 0)
	}

	host, err := mcp.NewMCPHost(g, mcp.MCPHostOptions{
		Name:       "koopa-mcp",
		Version:    "1.0.0",
		MCPServers: serverConfigs,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create MCP host: %w", err)
	}

	return &MCPManager{
		host: host,
	}, nil
}

// GetActiveTools retrieves tools from all active MCP servers
func (m *MCPManager) GetActiveTools(ctx context.Context, g *genkit.Genkit) ([]ai.Tool, error) {
	tools, err := m.host.GetActiveTools(ctx, g)
	if err != nil {
		return nil, fmt.Errorf("unable to get MCP tools: %w", err)
	}
	return tools, nil
}

// GetActiveResources retrieves resources from all active MCP servers
func (m *MCPManager) GetActiveResources(ctx context.Context) ([]ai.Resource, error) {
	resources, err := m.host.GetActiveResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get MCP resources: %w", err)
	}
	return resources, nil
}

// GetPrompt retrieves a prompt from the specified MCP server
func (m *MCPManager) GetPrompt(ctx context.Context, g *genkit.Genkit, serverName, promptName string, args map[string]string) (ai.Prompt, error) {
	prompt, err := m.host.GetPrompt(ctx, g, serverName, promptName, args)
	if err != nil {
		return nil, fmt.Errorf("unable to get MCP prompt: %w", err)
	}
	return prompt, nil
}

// Connect dynamically connects to a new MCP server
func (m *MCPManager) Connect(ctx context.Context, g *genkit.Genkit, serverName string, config mcp.MCPClientOptions) error {
	err := m.host.Connect(ctx, g, serverName, config)
	if err != nil {
		return fmt.Errorf("unable to connect to MCP server %s: %w", serverName, err)
	}
	return nil
}

// Disconnect disconnects from the specified MCP server
func (m *MCPManager) Disconnect(ctx context.Context, serverName string) error {
	err := m.host.Disconnect(ctx, serverName)
	if err != nil {
		return fmt.Errorf("unable to disconnect from MCP server %s: %w", serverName, err)
	}
	return nil
}

// Reconnect reconnects to the specified MCP server
func (m *MCPManager) Reconnect(ctx context.Context, serverName string) error {
	err := m.host.Reconnect(ctx, serverName)
	if err != nil {
		return fmt.Errorf("unable to reconnect to MCP server %s: %w", serverName, err)
	}
	return nil
}

// CreateMCPServer exposes Genkit tools as an MCP server
func CreateMCPServer(g *genkit.Genkit) *mcp.GenkitMCPServer {
	// Create MCP server, automatically exposing all registered tools
	server := mcp.NewMCPServer(g, mcp.MCPServerOptions{
		Name:    "koopa-mcp-server",
		Version: "1.0.0",
	})
	return server
}

// StartMCPServer starts the MCP server (stdio mode)
func StartMCPServer(server *mcp.GenkitMCPServer) error {
	log.Println("🔌 Starting Koopa MCP server...")
	if err := server.ServeStdio(); err != nil {
		return fmt.Errorf("MCP server startup failed: %w", err)
	}
	return nil
}
