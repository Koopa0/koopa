package tools

import (
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// toolNames contains all registered tool names
// This is the single source of truth for tool names to avoid duplication
var toolNames = []string{
	"currentTime",
	"readFile",
	"writeFile",
	"listFiles",
	"deleteFile",
	"executeCommand",
	"httpGet",
	"getEnv",
	"getFileInfo",
}

// GetToolNames returns all registered tool names
// This allows other packages to get the tool list without duplication
func GetToolNames() []string {
	return toolNames
}

// RegisterTools registers all available tools with Genkit
// Validators are passed as parameters and captured by closures (dependency injection pattern)
// This follows Go best practices: no package-level state, dependencies are explicit
func RegisterTools(
	g *genkit.Genkit,
	pathVal *security.PathValidator,
	cmdVal *security.CommandValidator,
	httpVal *security.HTTPValidator,
	envVal *security.EnvValidator,
) {
	// Register filesystem tools (5 tools)
	// Pass validators as parameters, closures will capture them
	registerFileTools(g, pathVal)

	// Register system tools (3 tools)
	registerSystemTools(g, cmdVal, envVal)

	// Register network tools (1 tool)
	registerNetworkTools(g, httpVal)
}
