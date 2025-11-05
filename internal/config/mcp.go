package config

import (
	"fmt"
	"os"

	"github.com/firebase/genkit/go/plugins/mcp"
)

// MCPConfig represents configuration for a single MCP server.
type MCPConfig struct {
	Name          string
	ClientOptions mcp.MCPClientOptions
}

// LoadMCPConfigs loads MCP server configurations from environment variables.
// This follows the 12-factor app methodology for configuration management.
//
// Supported MCP servers and their environment variables:
//
//   - GitHub: GITHUB_TOKEN or GITHUB_PERSONAL_ACCESS_TOKEN
//   - Notion: NOTION_API_KEY
//   - Slack: SLACK_BOT_TOKEN, SLACK_TEAM_ID
//   - Context7: Always enabled (CONTEXT7_API_KEY optional for higher rate limits)
//   - Cloudflare: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
//   - Linear: LINEAR_API_KEY
//
// Returns a slice of MCPConfig for all available servers.
func LoadMCPConfigs() []MCPConfig {
	var configs []MCPConfig

	// GitHub MCP Server
	// Supports both GITHUB_TOKEN (common) and GITHUB_PERSONAL_ACCESS_TOKEN (official)
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
	}
	if token != "" {
		configs = append(configs, MCPConfig{
			Name: "github",
			ClientOptions: mcp.MCPClientOptions{
				Name: "github",
				Stdio: &mcp.StdioConfig{
					Command: "npx",
					Args:    []string{"-y", "@modelcontextprotocol/server-github"},
					Env:     envMapToSlice(map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": token}),
				},
			},
		})
	}

	// Notion MCP Server
	if apiKey := os.Getenv("NOTION_API_KEY"); apiKey != "" {
		configs = append(configs, MCPConfig{
			Name: "notion",
			ClientOptions: mcp.MCPClientOptions{
				Name: "notion",
				Stdio: &mcp.StdioConfig{
					Command: "npx",
					Args:    []string{"-y", "@notionhq/mcp-server-notion"},
					Env:     envMapToSlice(map[string]string{"NOTION_API_KEY": apiKey}),
				},
			},
		})
	}

	// Slack MCP Server
	botToken := os.Getenv("SLACK_BOT_TOKEN")
	teamID := os.Getenv("SLACK_TEAM_ID")
	if botToken != "" && teamID != "" {
		configs = append(configs, MCPConfig{
			Name: "slack",
			ClientOptions: mcp.MCPClientOptions{
				Name: "slack",
				Stdio: &mcp.StdioConfig{
					Command: "npx",
					Args:    []string{"-y", "@modelcontextprotocol/server-slack"},
					Env: envMapToSlice(map[string]string{
						"SLACK_BOT_TOKEN": botToken,
						"SLACK_TEAM_ID":   teamID,
					}),
				},
			},
		})
	}

	// Context7 MCP Server
	// TEMPORARILY DISABLED FOR TESTING - Context7 can cause slow startup
	// API key is optional - provides higher rate limits and private repo access
	/*
	args := []string{"-y", "@upstash/context7-mcp@latest"}
	if apiKey := os.Getenv("CONTEXT7_API_KEY"); apiKey != "" {
		args = append(args, "--api-key", apiKey)
	}
	configs = append(configs, MCPConfig{
		Name: "context7",
		ClientOptions: mcp.MCPClientOptions{
			Name: "context7",
			Stdio: &mcp.StdioConfig{
				Command: "npx",
				Args:    args,
			},
		},
	})
	*/

	// Google Workspace MCP Server - Commented out (requires OAuth setup)
	// Multiple implementations exist with different OAuth requirements
	// Users should configure manually via claude_desktop_config.json if needed
	// Reference: https://github.com/taylorwilsdon/google_workspace_mcp

	// Cloudflare MCP Server
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	if apiToken != "" && accountID != "" {
		configs = append(configs, MCPConfig{
			Name: "cloudflare",
			ClientOptions: mcp.MCPClientOptions{
				Name: "cloudflare",
				Stdio: &mcp.StdioConfig{
					Command: "npx",
					Args:    []string{"-y", "@cloudflare/mcp-server-cloudflare"},
					Env: envMapToSlice(map[string]string{
						"CLOUDFLARE_API_TOKEN":  apiToken,
						"CLOUDFLARE_ACCOUNT_ID": accountID,
					}),
				},
			},
		})
	}

	// Linear MCP Server
	if apiKey := os.Getenv("LINEAR_API_KEY"); apiKey != "" {
		configs = append(configs, MCPConfig{
			Name: "linear",
			ClientOptions: mcp.MCPClientOptions{
				Name: "linear",
				Stdio: &mcp.StdioConfig{
					Command: "npx",
					Args:    []string{"-y", "@linear/mcp-server"},
					Env:     envMapToSlice(map[string]string{"LINEAR_API_KEY": apiKey}),
				},
			},
		})
	}

	return configs
}

// envMapToSlice converts a map of environment variables to the slice format
// required by Genkit's StdioConfig.Env field.
func envMapToSlice(m map[string]string) []string {
	if m == nil {
		return nil
	}
	result := make([]string, 0, len(m))
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}
