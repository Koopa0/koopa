package tools

import "strings"

// metadata.go defines tool safety metadata for the Koopa Agent Framework.
//
// This module provides a centralized registry of tool danger levels, enabling:
// - Clear categorization of tool safety characteristics
// - Runtime validation of dangerous operations
// - Enhanced system prompt guidance for LLM behavior

// DangerLevel indicates the risk level of a tool operation.
type DangerLevel int

const (
	// DangerLevelSafe represents read-only operations with no state modification.
	// Examples: read_file, list_files, get_file_info, current_time, web_fetch, get_env
	DangerLevelSafe DangerLevel = iota

	// DangerLevelWarning represents operations that modify state but are generally reversible.
	// Examples: write_file (can be overwritten)
	// These operations may require caution but don't typically cause data loss
	DangerLevelWarning

	// DangerLevelDangerous represents irreversible or destructive operations.
	// Examples: delete_file, execute_command (with rm, DROP DATABASE, etc.)
	// These operations MUST trigger request_confirmation before execution
	DangerLevelDangerous

	// DangerLevelCritical represents system-level destructive operations.
	// Examples: Format disk, shutdown system, delete entire directories
	// Reserved for future use - not currently assigned to any tool
	DangerLevelCritical
)

// String returns the human-readable name of the danger level.
func (d DangerLevel) String() string {
	switch d {
	case DangerLevelSafe:
		return "Safe"
	case DangerLevelWarning:
		return "Warning"
	case DangerLevelDangerous:
		return "Dangerous"
	case DangerLevelCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ToolMetadata defines business properties for tools.
// Follows design document specification (lines 601-605).
type ToolMetadata struct {
	// Name is the unique identifier of the tool.
	NameField string

	// RequiresConfirmation indicates if the tool MUST call requestConfirmation before execution.
	// This is true for all DangerLevelDangerous and DangerLevelCritical tools.
	RequiresConfirmation bool

	// DangerLevel classifies the safety level of the tool.
	DangerLevel DangerLevel

	// IsDangerousFunc is an optional function that dynamically determines if specific
	// parameters make this tool call dangerous.
	// Example: writeFile to /etc/passwd is more dangerous than writeFile to /tmp/test.txt
	// If nil, danger level is static (determined by DangerLevel field only).
	IsDangerousFunc func(params map[string]any) bool

	// Category organizes tools by domain (File, System, Network, Meta).
	// This field is not in the original design doc but is useful for documentation.
	Category string

	// Description provides a brief explanation of what the tool does.
	// This field is not in the original design doc but is useful for documentation.
	DescriptionField string
}

// Name returns the tool's name.
func (t *ToolMetadata) Name() string {
	return t.NameField
}

// Description returns the tool's description.
func (t *ToolMetadata) Description() string {
	return t.DescriptionField
}

// IsLongRunning indicates if the tool is long-running.
// Currently defaults to false for all tools using metadata.
func (t *ToolMetadata) IsLongRunning() bool {
	return false
}

// sensitivePaths are system paths that should never be written to by tools.
// This is hoisted to package level to avoid repeated allocation in IsDangerousFunc.
var sensitivePaths = []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/sys/", "/proc/"}

// toolMetadata is the central registry of all tool metadata.
// This is the single source of truth for tool safety classifications.
var toolMetadata = map[string]ToolMetadata{
	// File Operations
	ToolReadFile: {
		NameField:            ToolReadFile,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "File",
		DescriptionField:     "Read file contents (read-only, no modifications)",
	},
	ToolWriteFile: {
		NameField:            ToolWriteFile,
		RequiresConfirmation: true,
		DangerLevel:          DangerLevelWarning,
		IsDangerousFunc: func(params map[string]any) bool {
			// Check if writing to sensitive system paths
			if path, ok := params["path"].(string); ok {
				for _, prefix := range sensitivePaths {
					if strings.HasPrefix(path, prefix) {
						return true // Escalate to dangerous
					}
				}
			}
			return false // Normal warning level
		},
		Category:         "File",
		DescriptionField: "Create or overwrite files (modifies state, reversible)",
	},
	ToolListFiles: {
		NameField:            ToolListFiles,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "File",
		DescriptionField:     "List directory contents (read-only)",
	},
	ToolDeleteFile: {
		NameField:            ToolDeleteFile,
		RequiresConfirmation: true,
		DangerLevel:          DangerLevelDangerous,
		IsDangerousFunc:      nil, // Always dangerous
		Category:             "File",
		DescriptionField:     "Permanently delete files (irreversible, destructive)",
	},
	ToolGetFileInfo: {
		NameField:            ToolGetFileInfo,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "File",
		DescriptionField:     "Get file metadata (read-only)",
	},

	// System Operations
	ToolCurrentTime: {
		NameField:            ToolCurrentTime,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "System",
		DescriptionField:     "Get current system time (read-only)",
	},
	ToolExecuteCommand: {
		NameField:            ToolExecuteCommand,
		RequiresConfirmation: true,
		DangerLevel:          DangerLevelDangerous,
		IsDangerousFunc: func(params map[string]any) bool {
			// All executeCommand calls are dangerous by default
			// Future: Could parse command and detect destructive operations
			return true
		},
		Category:         "System",
		DescriptionField: "Execute shell commands (potentially destructive)",
	},
	ToolGetEnv: {
		NameField:            ToolGetEnv,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "System",
		DescriptionField:     "Read environment variables (read-only)",
	},

	// Network Operations
	ToolWebSearch: {
		NameField:            ToolWebSearch,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "Network",
		DescriptionField:     "Search the web for information (read-only)",
	},
	ToolWebFetch: {
		NameField:            ToolWebFetch,
		RequiresConfirmation: false,
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "Network",
		DescriptionField:     "Fetch data from HTTP endpoints (read-only)",
	},

	// Meta Tools (Human-in-the-Loop)
	"request_confirmation": {
		NameField:            "request_confirmation",
		RequiresConfirmation: false, // request_confirmation itself doesn't need confirmation
		DangerLevel:          DangerLevelSafe,
		IsDangerousFunc:      nil,
		Category:             "Meta",
		DescriptionField:     "Request user approval for dangerous operations (safety mechanism)",
	},
}

// GetToolMetadata retrieves metadata for a specific tool.
// Returns the metadata and a boolean indicating if the tool was found.
//
// Usage:
//
//	if meta, ok := tools.GetToolMetadata(tools.ToolDeleteFile); ok {
//	    if meta.RequiresConfirmation {
//	        // Must call request_confirmation first
//	    }
//	}
func GetToolMetadata(toolName string) (ToolMetadata, bool) {
	meta, ok := toolMetadata[toolName]
	return meta, ok
}

// GetAllToolMetadata returns a copy of all tool metadata.
// Useful for documentation generation and validation.
func GetAllToolMetadata() map[string]ToolMetadata {
	// Return a copy to prevent external mutation
	result := make(map[string]ToolMetadata, len(toolMetadata))
	for k, v := range toolMetadata {
		result[k] = v
	}
	return result
}

// IsDangerous returns true if the tool is classified as DangerLevelDangerous or DangerLevelCritical.
// This is a convenience function for quick safety checks.
//
// Usage:
//
//	if tools.IsDangerous(tools.ToolDeleteFile) {
//	    // Require confirmation
//	}
func IsDangerous(toolName string) bool {
	if meta, ok := toolMetadata[toolName]; ok {
		return meta.DangerLevel == DangerLevelDangerous || meta.DangerLevel == DangerLevelCritical
	}
	// Unknown tools are treated as safe by default (fail-safe)
	return false
}

// RequiresConfirmation returns true if the tool requires user confirmation before execution.
// Considers both static RequiresConfirmation flag and dynamic IsDangerousFunc.
//
// Usage:
//
//	if tools.RequiresConfirmation(tools.ToolWriteFile, params) {
//	    // Must call request_confirmation first
//	}
func RequiresConfirmation(toolName string, params map[string]any) bool {
	meta, ok := toolMetadata[toolName]
	if !ok {
		// Unknown tools don't require confirmation (fail-safe)
		return false
	}

	// Check static flag
	if meta.RequiresConfirmation {
		return true
	}

	// Check dynamic function
	if meta.IsDangerousFunc != nil && meta.IsDangerousFunc(params) {
		return true
	}

	return false
}

// GetDangerLevel returns the danger level of a tool.
// Returns DangerLevelSafe for unknown tools (fail-safe default).
func GetDangerLevel(toolName string) DangerLevel {
	if meta, ok := toolMetadata[toolName]; ok {
		return meta.DangerLevel
	}
	return DangerLevelSafe
}

// ListToolsByDangerLevel returns all tools matching the specified danger level.
// Useful for generating documentation or validation checks.
func ListToolsByDangerLevel(level DangerLevel) []ToolMetadata {
	var result []ToolMetadata

	for _, meta := range toolMetadata {
		if meta.DangerLevel == level {
			result = append(result, meta)
		}
	}

	return result
}
