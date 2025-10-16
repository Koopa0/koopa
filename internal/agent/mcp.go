package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/mcp"
)

// MCPManager 管理 MCP 客戶端連接
type MCPManager struct {
	host *mcp.MCPHost
}

// NewMCPManager 創建新的 MCP 管理器（可選配置 MCP 伺服器）
func NewMCPManager(ctx context.Context, g *genkit.Genkit, serverConfigs []mcp.MCPServerConfig) (*MCPManager, error) {
	// 如果沒有提供配置，使用空配置（允許之後動態添加）
	if serverConfigs == nil {
		serverConfigs = make([]mcp.MCPServerConfig, 0)
	}

	host, err := mcp.NewMCPHost(g, mcp.MCPHostOptions{
		Name:       "koopa-mcp",
		Version:    "1.0.0",
		MCPServers: serverConfigs,
	})
	if err != nil {
		return nil, fmt.Errorf("無法創建 MCP 主機: %w", err)
	}

	return &MCPManager{
		host: host,
	}, nil
}

// GetActiveTools 獲取所有活躍 MCP 伺服器的工具
func (m *MCPManager) GetActiveTools(ctx context.Context, g *genkit.Genkit) ([]ai.Tool, error) {
	tools, err := m.host.GetActiveTools(ctx, g)
	if err != nil {
		return nil, fmt.Errorf("無法獲取 MCP 工具: %w", err)
	}
	return tools, nil
}

// GetActiveResources 獲取所有活躍 MCP 伺服器的資源
func (m *MCPManager) GetActiveResources(ctx context.Context) ([]ai.Resource, error) {
	resources, err := m.host.GetActiveResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("無法獲取 MCP 資源: %w", err)
	}
	return resources, nil
}

// GetPrompt 從指定的 MCP 伺服器獲取 prompt
func (m *MCPManager) GetPrompt(ctx context.Context, g *genkit.Genkit, serverName, promptName string, args map[string]string) (ai.Prompt, error) {
	prompt, err := m.host.GetPrompt(ctx, g, serverName, promptName, args)
	if err != nil {
		return nil, fmt.Errorf("無法獲取 MCP prompt: %w", err)
	}
	return prompt, nil
}

// Connect 動態連接到新的 MCP 伺服器
func (m *MCPManager) Connect(ctx context.Context, g *genkit.Genkit, serverName string, config mcp.MCPClientOptions) error {
	err := m.host.Connect(ctx, g, serverName, config)
	if err != nil {
		return fmt.Errorf("無法連接到 MCP 伺服器 %s: %w", serverName, err)
	}
	return nil
}

// Disconnect 斷開與指定 MCP 伺服器的連接
func (m *MCPManager) Disconnect(ctx context.Context, serverName string) error {
	err := m.host.Disconnect(ctx, serverName)
	if err != nil {
		return fmt.Errorf("無法斷開 MCP 伺服器 %s: %w", serverName, err)
	}
	return nil
}

// Reconnect 重新連接到指定的 MCP 伺服器
func (m *MCPManager) Reconnect(ctx context.Context, serverName string) error {
	err := m.host.Reconnect(ctx, serverName)
	if err != nil {
		return fmt.Errorf("無法重新連接到 MCP 伺服器 %s: %w", serverName, err)
	}
	return nil
}

// CreateMCPServer 將 Genkit 工具暴露為 MCP 伺服器
func CreateMCPServer(g *genkit.Genkit) *mcp.GenkitMCPServer {
	// 創建 MCP 伺服器，自動暴露所有已註冊的工具
	server := mcp.NewMCPServer(g, mcp.MCPServerOptions{
		Name:    "koopa-mcp-server",
		Version: "1.0.0",
	})
	return server
}

// StartMCPServer 啟動 MCP 伺服器（stdio 模式）
func StartMCPServer(server *mcp.GenkitMCPServer) error {
	log.Println("🔌 啟動 Koopa MCP 伺服器...")
	if err := server.ServeStdio(); err != nil {
		return fmt.Errorf("MCP 伺服器啟動失敗: %w", err)
	}
	return nil
}
