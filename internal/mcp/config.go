package mcp

// config.go handles MCP server configuration loading and filtering.
//
// LoadConfigs() loads MCP server configurations from config.yaml with:
//   - Whitelist/blacklist filtering (blacklist takes precedence)
//   - Environment variable resolution ($VAR_NAME syntax, Gemini CLI-compatible)
//   - Validation and conversion to Genkit MCPServerConfig format
//
// Follows explicit configuration principle - no auto-detection, all servers must be defined in config.

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/firebase/genkit/go/plugins/mcp"
	"github.com/koopa0/koopa-cli/internal/config"
)

// LoadConfigs loads MCP server configurations from config file.
// It applies allowed/excluded filters and resolves environment variables.
//
// Parameters:
//   - cfg: Application configuration containing MCP settings
//
// Returns:
//   - []Config: Filtered list of MCP server configurations to connect
//   - error: If configuration is invalid
func LoadConfigs(cfg *config.Config) ([]Config, error) {
	// 1. Check if any servers are configured
	if len(cfg.MCPServers) == 0 {
		slog.Info("no MCP servers configured, skipping MCP initialization")
		return []Config{}, nil
	}

	slog.Info("loading MCP configurations",
		"configured_servers", len(cfg.MCPServers),
		"allowed", cfg.MCP.Allowed,
		"excluded", cfg.MCP.Excluded)

	// 2. Build candidate list from configured servers
	var candidates []Config
	for name, serverCfg := range cfg.MCPServers {
		// Validate required fields
		if serverCfg.Command == "" {
			slog.Warn("skipping MCP server: missing required 'command' field",
				"server", name)
			continue
		}

		// Resolve environment variables in env map
		resolvedEnv := resolveEnvVars(serverCfg.Env)

		// Note: Timeout is handled by caller (cmd/chat.go) via context
		// Server-specific timeout in config.MCPServer is reserved for future use

		// Build Config
		config := Config{
			Name: name,
			ClientOptions: mcp.MCPClientOptions{
				Name: name,
				Stdio: &mcp.StdioConfig{
					Command: serverCfg.Command,
					Args:    serverCfg.Args,
					Env:     envMapToSlice(resolvedEnv),
				},
			},
		}

		candidates = append(candidates, config)
	}

	slog.Info("built candidate MCP servers",
		"candidate_count", len(candidates))

	// 3. Apply blacklist (highest priority)
	if len(cfg.MCP.Excluded) > 0 {
		before := len(candidates)
		candidates = filterExcluded(candidates, cfg.MCP.Excluded)
		slog.Info("applied MCP blacklist",
			"excluded", cfg.MCP.Excluded,
			"removed_count", before-len(candidates))
	}

	// 4. Apply whitelist (if specified)
	if len(cfg.MCP.Allowed) > 0 {
		before := len(candidates)
		candidates = filterAllowed(candidates, cfg.MCP.Allowed)
		slog.Info("applied MCP whitelist",
			"allowed", cfg.MCP.Allowed,
			"kept_count", len(candidates),
			"filtered_out", before-len(candidates))
	}

	if len(candidates) == 0 {
		slog.Info("no MCP servers after filtering")
	} else {
		serverNames := make([]string, len(candidates))
		for i, c := range candidates {
			serverNames[i] = c.Name
		}
		slog.Info("final MCP servers to connect",
			"servers", serverNames)
	}

	return candidates, nil
}

// resolveEnvVars resolves environment variable references in format $VAR_NAME
// This follows Gemini CLI's convention for environment variable substitution.
//
// Example:
//
//	Input:  {"API_KEY": "$GITHUB_TOKEN"}
//	Output: {"API_KEY": "actual_token_value"}
func resolveEnvVars(envMap map[string]string) map[string]string {
	if envMap == nil {
		return nil
	}

	resolved := make(map[string]string, len(envMap))
	for key, value := range envMap {
		// Support Gemini CLI's $VAR_NAME syntax
		if strings.HasPrefix(value, "$") {
			envName := strings.TrimPrefix(value, "$")
			envValue := os.Getenv(envName)
			if envValue == "" {
				slog.Warn("environment variable not set for MCP server",
					"env_var", envName,
					"mapped_to", key)
			}
			resolved[key] = envValue
		} else {
			// Literal value (not recommended for secrets, but supported)
			resolved[key] = value
		}
	}
	return resolved
}

// filterExcluded removes excluded servers from candidates
func filterExcluded(candidates []Config, excluded []string) []Config {
	if len(excluded) == 0 {
		return candidates
	}

	excludedSet := make(map[string]bool, len(excluded))
	for _, name := range excluded {
		excludedSet[name] = true
	}

	filtered := make([]Config, 0, len(candidates))
	for _, candidate := range candidates {
		if !excludedSet[candidate.Name] {
			filtered = append(filtered, candidate)
		} else {
			slog.Info("excluded MCP server", "server", candidate.Name)
		}
	}
	return filtered
}

// filterAllowed keeps only allowed servers
func filterAllowed(candidates []Config, allowed []string) []Config {
	if len(allowed) == 0 {
		return candidates
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = true
	}

	filtered := make([]Config, 0, len(candidates))
	for _, candidate := range candidates {
		if allowedSet[candidate.Name] {
			filtered = append(filtered, candidate)
		} else {
			slog.Info("filtered out MCP server (not in allowed list)",
				"server", candidate.Name)
		}
	}
	return filtered
}

// envMapToSlice converts environment variable map to KEY=VALUE slice format
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
