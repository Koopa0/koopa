package security

import (
	"fmt"
	"strings"
)

// CommandValidator command validator
// Used to prevent command injection attacks (CWE-78)
type CommandValidator struct {
	blacklist []string
	whitelist []string // If non-empty, only allow commands in the whitelist
}

// NewCommandValidator creates a command validator
func NewCommandValidator() *CommandValidator {
	return &CommandValidator{
		blacklist: []string{
			// Dangerous deletion commands
			"rm -rf /",
			"rm -rf ~",
			"rm -rf /*",
			"rm -rf $HOME",

			// Disk operations
			"dd if=/dev/zero",
			"dd if=/dev/urandom",
			"mkfs",
			"format",
			"fdisk",

			// Device access
			"> /dev/",
			"< /dev/",

			// Remote script execution
			"curl", // Needs special handling
			"wget", // Needs special handling

			// Fork bombs
			":()",
			"fork",

			// System shutdown
			"shutdown",
			"reboot",
			"halt",
			"poweroff",

			// Privilege escalation
			"sudo su",
			"su -",
		},
	}
}

// NewStrictCommandValidator creates a strict command validator (whitelist mode)
// Only allows common safe commands
func NewStrictCommandValidator() *CommandValidator {
	return &CommandValidator{
		blacklist: []string{}, // Whitelist mode doesn't need blacklist
		whitelist: []string{
			// File operations
			"ls", "cat", "head", "tail", "less", "more",
			"grep", "find", "wc", "sort", "uniq",

			// Directory operations
			"pwd", "cd", "mkdir", "tree",

			// System information
			"date", "whoami", "hostname", "uname",
			"df", "du", "free", "top", "ps",

			// Network (read-only)
			"ping", "traceroute", "nslookup", "dig",

			// Git
			"git status", "git log", "git diff", "git branch",

			// Other
			"echo", "printf", "which", "whereis",
		},
	}
}

// ValidateCommand validates whether a command is safe
// cmd: command name
// args: command arguments
func (v *CommandValidator) ValidateCommand(cmd string, args []string) error {
	// Build full command
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd = cmd + " " + strings.Join(args, " ")
	}

	// If there's a whitelist, only check the whitelist
	if len(v.whitelist) > 0 {
		return v.checkWhitelist(cmd, fullCmd)
	}

	// Otherwise check the blacklist
	return v.checkBlacklist(fullCmd)
}

// checkWhitelist checks if the command is in the whitelist
func (v *CommandValidator) checkWhitelist(cmd string, fullCmd string) error {
	// Check if command is in the whitelist
	for _, allowed := range v.whitelist {
		if cmd == allowed || strings.HasPrefix(fullCmd, allowed) {
			return nil
		}
	}

	return fmt.Errorf("command '%s' is not in whitelist", cmd)
}

// checkBlacklist checks if the command contains dangerous patterns
func (v *CommandValidator) checkBlacklist(fullCmd string) error {
	// Check blacklist
	for _, pattern := range v.blacklist {
		if strings.Contains(fullCmd, pattern) {
			return fmt.Errorf("command contains dangerous pattern: '%s'", pattern)
		}
	}

	// Check dangerous characters (possible command injection)
	dangerousChars := map[string]string{
		";":  "command separator",
		"|":  "pipe",
		"&":  "background execution",
		"`":  "command substitution",
		"$":  "variable substitution",
		"(":  "subshell",
		")":  "subshell",
		"<":  "input redirection",
		">":  "output redirection",
		"\\": "escape character",
		"\n": "newline",
	}

	for char, desc := range dangerousChars {
		if strings.Contains(fullCmd, char) {
			return fmt.Errorf("command contains dangerous character '%s' (%s)", char, desc)
		}
	}

	// Special check for curl and wget (often used to download malicious scripts)
	lowerCmd := strings.ToLower(fullCmd)
	if strings.Contains(lowerCmd, "curl") || strings.Contains(lowerCmd, "wget") {
		// Check for pipe or script execution
		if strings.Contains(lowerCmd, "bash") ||
			strings.Contains(lowerCmd, "sh") ||
			strings.Contains(lowerCmd, "python") ||
			strings.Contains(lowerCmd, "perl") {
			return fmt.Errorf("direct script execution with curl/wget is prohibited")
		}
	}

	return nil
}

// IsCommandSafe quickly checks if a command string is obviously unsafe
// This is a lightweight check and should not be used as the sole validation
func IsCommandSafe(cmd string) bool {
	// Check for obvious dangerous patterns
	dangerousPatterns := []string{
		"rm -rf",
		"mkfs",
		"format",
		"dd if=",
		"> /dev/",
		"sudo",
		"su -",
		"shutdown",
		"reboot",
	}

	lowerCmd := strings.ToLower(cmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerCmd, pattern) {
			return false
		}
	}

	return true
}

// SanitizeCommandArgs sanitizes command arguments, removing potentially dangerous characters
// Note: This cannot replace complete validation, it's just an additional layer of protection
func SanitizeCommandArgs(args []string) []string {
	sanitized := make([]string, 0, len(args))

	for _, arg := range args {
		// Trim leading and trailing whitespace
		arg = strings.TrimSpace(arg)

		// Skip empty arguments
		if arg == "" {
			continue
		}

		// Check for dangerous characters
		if strings.ContainsAny(arg, ";|&`$()<>\\") {
			// If it contains dangerous characters, wrap in quotes
			// But this still isn't safe enough, should be caught by ValidateCommand
			arg = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}

		sanitized = append(sanitized, arg)
	}

	return sanitized
}
