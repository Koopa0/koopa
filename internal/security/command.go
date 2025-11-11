package security

import (
	"fmt"
	"log/slog"
	"strings"
)

// Command validates commands to prevent injection attacks.
// Used to prevent command injection attacks (CWE-78).
type Command struct {
	blacklist []string
	whitelist []string // If non-empty, only allow commands in the whitelist
}

// NewCommand creates a new Command validator with whitelist mode (secure by default).
// Only allows explicitly whitelisted safe commands to prevent command injection attacks.
//
// Allowed commands include:
//   - File operations: ls, cat, head, tail, grep, find, etc.
//   - Directory operations: pwd, cd, mkdir, tree
//   - System info: date, whoami, hostname, uname, df, du, ps
//   - Network (read-only): ping, traceroute, nslookup, dig
//   - Version control: git
//
// Dangerous commands like rm, chmod, mv, python, etc. are blocked by default.
func NewCommand() *Command {
	return &Command{
		blacklist: []string{}, // Whitelist mode doesn't need blacklist
		whitelist: []string{
			// File operations (read-only and safe writes)
			"ls", "cat", "head", "tail", "less", "more",
			"grep", "find", "wc", "sort", "uniq",

			// Directory operations
			"pwd", "cd", "mkdir", "tree",

			// System information (read-only)
			"date", "whoami", "hostname", "uname",
			"df", "du", "free", "top", "ps",

			// Network (read-only)
			"ping", "traceroute", "nslookup", "dig",

			// Version control
			"git",

			// Build tools (commonly needed for development)
			"go", "npm", "yarn", "make",

			// Other utilities
			"echo", "printf", "which", "whereis",
		},
	}
}

// ValidateCommand validates whether a command is safe.
//
// SECURITY NOTE: This validator is designed for use with exec.Command(cmd, args...),
// which does NOT pass arguments through a shell. Therefore:
// - Special characters ($, |, >, <, etc.) in args[] are SAFE (treated as literals)
// - We only validate the command name (cmd) strictly
// - Args are checked for obviously malicious patterns but not for shell metacharacters
//
// Parameters:
//   - cmd: command name (executable)
//   - args: command arguments (passed directly to exec.Command, not shell-interpreted)
func (v *Command) ValidateCommand(cmd string, args []string) error {
	// 1. Check for empty command
	if strings.TrimSpace(cmd) == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// 2. Validate command name only (no args yet)
	if err := v.validateCommandName(cmd); err != nil {
		return err
	}

	// 3. If whitelist mode, check if command is allowed
	if len(v.whitelist) > 0 {
		// In whitelist mode, only check the command name
		if !v.isCommandInWhitelist(cmd) {
			slog.Warn("command not in whitelist",
				"command", cmd,
				"whitelist", v.whitelist,
				"security_event", "command_whitelist_violation")
			return fmt.Errorf("command '%s' is not in whitelist", cmd)
		}
	}

	// 4. Check args for obviously malicious patterns
	// NOTE: We do NOT check for shell metacharacters (|, $, >, etc.) because
	// exec.Command treats them as literal strings, not shell operators
	for i, arg := range args {
		if err := v.validateArgument(arg); err != nil {
			slog.Warn("dangerous argument detected",
				"command", cmd,
				"arg_index", i,
				"arg_value", arg,
				"error", err,
				"security_event", "dangerous_argument")
			return fmt.Errorf("argument %d is unsafe: %w", i, err)
		}
	}

	// 5. Check full command string (cmd + args) for dangerous patterns
	// Some dangerous patterns span command and arguments (e.g., "rm -rf /")
	fullCmd := strings.ToLower(cmd + " " + strings.Join(args, " "))
	for _, pattern := range v.blacklist {
		if strings.Contains(fullCmd, strings.ToLower(pattern)) {
			slog.Warn("command+args match dangerous pattern",
				"command", cmd,
				"args", args,
				"full_command", fullCmd,
				"dangerous_pattern", pattern,
				"security_event", "dangerous_command_combination")
			return fmt.Errorf("command contains dangerous pattern: '%s'", pattern)
		}
	}

	return nil
}

// validateCommandName validates the command name (executable) only.
// Checks blacklist patterns and shell injection attempts in the command name itself.
func (v *Command) validateCommandName(cmd string) error {
	// Normalize command name
	cmd = strings.TrimSpace(strings.ToLower(cmd))

	// Check blacklisted command patterns
	for _, pattern := range v.blacklist {
		if strings.Contains(cmd, strings.ToLower(pattern)) {
			slog.Warn("command matches blacklisted pattern",
				"command", cmd,
				"dangerous_pattern", pattern,
				"security_event", "command_blacklist_violation")
			return fmt.Errorf("command contains dangerous pattern: '%s'", pattern)
		}
	}

	// Check for shell metacharacters in command name itself
	// (These would indicate shell injection attempt)
	shellMetachars := []string{";", "|", "&", "`", "\n", ">", "<", "$", "(", ")"}
	for _, char := range shellMetachars {
		if strings.Contains(cmd, char) {
			slog.Warn("command name contains shell metacharacter",
				"command", cmd,
				"character", char,
				"security_event", "shell_injection_in_command_name")
			return fmt.Errorf("command name contains shell metacharacter: '%s'", char)
		}
	}

	return nil
}

// isCommandInWhitelist checks if command name is in the whitelist.
func (v *Command) isCommandInWhitelist(cmd string) bool {
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	for _, allowed := range v.whitelist {
		if cmdLower == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

// validateArgument checks if an argument contains obviously malicious patterns.
//
// IMPORTANT: This function does NOT check for shell metacharacters like $, |, >, <
// because when using exec.Command(cmd, args...), these are treated as literal strings
// and are safe. We only check for truly dangerous patterns like:
// - Embedded dangerous commands (e.g., "rm -rf /")
// - Null bytes
// - Extremely long arguments (possible buffer overflow)
func (v *Command) validateArgument(arg string) error {
	// Check for null bytes (often used in injection attacks)
	if strings.Contains(arg, "\x00") {
		return fmt.Errorf("argument contains null byte")
	}

	// Check for unreasonably long arguments (possible DoS or buffer overflow)
	if len(arg) > 10000 {
		return fmt.Errorf("argument too long (%d bytes, max 10000)", len(arg))
	}

	// Check for embedded dangerous command patterns
	// These are suspicious even in arguments
	argLower := strings.ToLower(arg)
	dangerousPatterns := []string{
		"rm -rf /",
		"rm -rf /*",
		"rm -rf ~",
		"mkfs",
		"dd if=/dev/zero",
		"dd if=/dev/urandom",
		"shutdown",
		"reboot",
		"sudo su",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(argLower, pattern) {
			return fmt.Errorf("argument contains dangerous pattern: %s", pattern)
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

// QuoteCommandArgs quotes command arguments containing dangerous characters
// This wraps arguments in single quotes for shell safety
// Note: This cannot replace complete validation via ValidateCommand()
func QuoteCommandArgs(args []string) []string {
	quoted := make([]string, 0, len(args))

	for _, arg := range args {
		// Trim leading and trailing whitespace
		arg = strings.TrimSpace(arg)

		// Skip empty arguments
		if arg == "" {
			continue
		}

		// Check for dangerous characters that need quoting
		if strings.ContainsAny(arg, ";|&`$()<>\\") {
			// Wrap in single quotes using POSIX shell escaping
			// This escapes embedded single quotes: 'it'\''s' → it's
			arg = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}

		quoted = append(quoted, arg)
	}

	return quoted
}
