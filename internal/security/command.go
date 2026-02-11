package security

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

// Command validates commands to prevent injection attacks.
// Used to prevent command injection attacks (CWE-78).
type Command struct {
	whitelist          []string            // Only allow commands in this list
	blockedSubcommands map[string][]string // cmd → blocked first-arg subcommands
	blockedArgPatterns map[string][]string // cmd → blocked argument patterns (any position)
}

// NewCommand creates a new Command validator with whitelist mode (secure by default).
// Only allows explicitly whitelisted safe commands to prevent command injection attacks.
//
// Allowed commands include:
//   - File listing: ls, wc, sort, uniq, tree
//   - Directory: pwd, cd
//   - System info: date, whoami, hostname, uname, df, du, ps
//   - Network (read-only): ping, traceroute, nslookup, dig
//   - Version control: git (with subcommand restrictions)
//   - Build tools: go, npm, yarn (with subcommand restrictions)
//
// File reading commands (cat, head, tail, grep, find) are NOT whitelisted.
// Use the read_file/list_files tools instead — they enforce path validation.
// make and mkdir are NOT whitelisted — make can execute arbitrary Makefile targets.
func NewCommand() *Command {
	return &Command{
		whitelist: []string{
			// File listing (metadata only — no content reading)
			"ls", "wc", "sort", "uniq",

			// Directory operations
			"pwd", "cd", "tree",

			// System information (read-only)
			"date", "whoami", "hostname", "uname",
			"df", "du", "free", "top", "ps",

			// Network (read-only)
			"ping", "traceroute", "nslookup", "dig",

			// Version control (with subcommand restrictions)
			"git",

			// Build tools (commonly needed for development)
			// NOTE: subcommand restrictions apply (see blockedSubcommands)
			"go", "npm", "yarn",

			// Other utilities
			"echo", "printf", "which", "whereis",
		},
		// Blocked subcommands: first argument must NOT match these.
		// Prevents whitelisted commands from executing arbitrary code.
		blockedSubcommands: map[string][]string{
			"go":   {"run", "generate", "tool"},
			"npm":  {"run", "exec", "start", "explore"},
			"yarn": {"run", "exec", "start"},
			"git":  {"filter-branch", "config", "difftool", "mergetool"},
		},
		blockedArgPatterns: map[string][]string{},
	}
}

// Validate validates whether a command is safe to execute.
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
func (v *Command) Validate(cmd string, args []string) error {
	// 1. Check for empty command
	if strings.TrimSpace(cmd) == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// 2. Validate command name only (no args yet)
	if err := validateCommandName(cmd); err != nil {
		return fmt.Errorf("validating command name: %w", err)
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

	// 4. Check blocked subcommands (e.g., "go run", "npm exec")
	if err := v.validateSubcommands(cmd, args); err != nil {
		return err
	}

	// 5. Check args for obviously malicious patterns
	// NOTE: We do NOT check for shell metacharacters (|, $, >, etc.) because
	// exec.Command treats them as literal strings, not shell operators
	for i, arg := range args {
		if err := validateArgument(arg); err != nil {
			slog.Warn("dangerous argument detected",
				"command", cmd,
				"arg_index", i,
				"arg_value", arg,
				"error", err,
				"security_event", "dangerous_argument")
			return fmt.Errorf("argument %d is unsafe: %w", i, err)
		}
	}

	return nil
}

// shellMetachars lists characters that indicate shell injection in a command name.
const shellMetachars = ";|&`\n><$()"

// validateCommandName validates the command name (executable) only.
// Checks for shell injection attempts in the command name itself.
func validateCommandName(cmd string) error {
	// Normalize command name
	cmd = strings.TrimSpace(strings.ToLower(cmd))

	// Check for shell metacharacters in command name itself
	// (These would indicate shell injection attempt)
	if i := strings.IndexAny(cmd, shellMetachars); i >= 0 {
		char := string(cmd[i])
		slog.Warn("command name contains shell metacharacter",
			"command", cmd,
			"character", char,
			"security_event", "shell_injection_in_command_name")
		return fmt.Errorf("command name contains shell metacharacter: %q", char)
	}

	return nil
}

// isCommandInWhitelist checks if command name is in the whitelist.
func (v *Command) isCommandInWhitelist(cmd string) bool {
	cmdTrimmed := strings.TrimSpace(cmd)
	for _, allowed := range v.whitelist {
		if strings.EqualFold(cmdTrimmed, allowed) {
			return true
		}
	}
	return false
}

// validateSubcommands checks if a whitelisted command is being used with a
// dangerous subcommand that would allow arbitrary code execution.
// For example, "go" is whitelisted but "go run" is blocked.
func (v *Command) validateSubcommands(cmd string, args []string) error {
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))

	// Check blocked subcommands (first argument)
	if blocked, ok := v.blockedSubcommands[cmdLower]; ok && len(args) > 0 {
		firstArg := strings.ToLower(strings.TrimSpace(args[0]))
		if slices.Contains(blocked, firstArg) {
			slog.Warn("blocked subcommand",
				"command", cmd,
				"subcommand", args[0],
				"security_event", "blocked_subcommand")
			return fmt.Errorf("subcommand '%s %s' is not allowed (can execute arbitrary code)", cmd, args[0])
		}
	}

	// Check blocked argument patterns (any position)
	if blocked, ok := v.blockedArgPatterns[cmdLower]; ok {
		for _, arg := range args {
			argLower := strings.ToLower(strings.TrimSpace(arg))
			for _, pattern := range blocked {
				// Match exact or flag=value form (e.g., "--eval" matches "--eval=cmd")
				if argLower == pattern || strings.HasPrefix(argLower, pattern+"=") {
					slog.Warn("blocked argument pattern",
						"command", cmd,
						"argument", arg,
						"security_event", "blocked_argument_pattern")
					return fmt.Errorf("argument '%s' is not allowed with '%s' (can execute arbitrary code)", arg, cmd)
				}
			}
		}
	}

	return nil
}

// dangerousArgPatterns lists embedded command patterns that are dangerous
// even when passed as arguments via exec.Command.
var dangerousArgPatterns = []string{
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

// validateArgument checks if an argument contains obviously malicious patterns.
//
// IMPORTANT: This function does NOT check for shell metacharacters like $, |, >, <
// because when using exec.Command(cmd, args...), these are treated as literal strings
// and are safe. We only check for truly dangerous patterns like:
// - Embedded dangerous commands (e.g., "rm -rf /")
// - Null bytes
// - Extremely long arguments (possible buffer overflow)
func validateArgument(arg string) error {
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
	for _, pattern := range dangerousArgPatterns {
		if strings.Contains(argLower, pattern) {
			return fmt.Errorf("argument contains dangerous pattern: %s", pattern)
		}
	}

	return nil
}
