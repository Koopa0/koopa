package security

import (
	"fmt"
	"slices"
	"strings"
)

// Command validates commands to prevent injection attacks.
// Used to prevent command injection attacks (CWE-78).
type Command struct {
	allowList          []string            // Only allow commands in this list
	allowedSubcommands map[string][]string // cmd → ONLY these subcommands allowed (default-deny)
	blockedArgPatterns map[string][]string // cmd → blocked flags/args at any position
	blockedEnvPrefixes []string            // env var prefixes that must not appear in arguments
}

// NewCommand creates a new Command validator with allow-list mode (secure by default).
// Only explicitly allowed commands may execute; all others are denied.
//
// Allowed commands include:
//   - File listing: ls, tree
//   - Directory: pwd, cd
//   - System info: date, whoami, hostname, uname, df, du, ps
//   - Version control: git (with subcommand allowlist)
//   - Build tools: go, npm, yarn (with subcommand allowlist)
//
// Excluded by design:
//   - cat, head, tail, grep, find — use read_file/list_files (path validation)
//   - sort, uniq, wc — read arbitrary files, bypass path validation (F5)
//   - ping, traceroute, nslookup, dig — internal network reconnaissance (F8)
//   - echo, printf — CWE-78 exfiltration relay risk
//   - make, mkdir — make executes arbitrary Makefile targets
//
// Commands with allowedSubcommands use default-deny: any subcommand not
// explicitly listed is blocked. This prevents bypass via unknown subcommands.
// Additionally, blockedArgPatterns blocks dangerous flags at ANY argument
// position (e.g., git -c, git --no-index) to prevent flag-based bypass (F1).
func NewCommand() *Command {
	return &Command{
		allowList: []string{
			// File listing (metadata only — no content reading)
			"ls",

			// Directory operations
			"pwd", "cd", "tree",

			// System information (read-only)
			"date", "whoami", "hostname", "uname",
			"df", "du", "free", "top", "ps",

			// Version control (with subcommand allowlist)
			"git",

			// Build tools (with subcommand allowlist)
			"go", "npm", "yarn",

			// Other utilities
			"which", "whereis",
		},
		// Allowed subcommands: default-deny mode.
		// If a command is listed here, ONLY these subcommands are permitted.
		// Any subcommand not in the list is blocked.
		// Prevents RCE via: go test (F2), npm install, git grep/archive (F3).
		allowedSubcommands: map[string][]string{
			"git": {
				// Read-only operations only — no write/mutate commands
				// NOTE: "branch" and "tag" excluded — destructive flags (-D, -d, -m, -f)
				// cannot be safely blocked without colliding with legitimate read-only
				// flags (e.g., git diff -M). Use "git log --oneline --decorate" instead.
				"status", "remote", "rev-parse", "describe",
				"log", "diff", "show", "blame",
			},
			"go": {
				// Metadata (no code execution)
				"version", "env",
				// Analysis (no code execution)
				"vet", "doc",
				// Formatting
				"fmt",
				// Read-only query
				"list",
				// NOTE: "mod" and "get" are intentionally excluded.
				// "go mod" can execute build scripts via tool directives.
				// "go get" downloads and may compile arbitrary code.
			},
			"npm": {
				// Read-only queries (no script execution)
				"version", "outdated",
				"view", "info", "audit", "why",
				"explain", "search",
				// NOTE: "list", "ls", "pack" excluded — trigger lifecycle scripts.
			},
			"yarn": {
				// Read-only queries (no script execution)
				"version", "info",
				"outdated", "why", "audit",
				// NOTE: "list" excluded — may trigger lifecycle hooks.
			},
		},
		// Blocked argument patterns: checked at ANY position in args[].
		// Prevents flag-based bypass of subcommand allowlist.
		// F1: git -c alias.x=!cmd, git --config-env, git --exec-path
		// F3: git diff --no-index /etc/passwd /dev/null
		blockedArgPatterns: map[string][]string{
			"git": {"-c", "--config-env", "--exec-path", "--no-replace-objects", "--no-index"},
			"npm": {"--eval", "--require"},
		},
		// Blocked environment variable prefixes in arguments.
		// Prevents injection of build-influencing env vars (CWE-78).
		blockedEnvPrefixes: []string{
			"GOFLAGS=", "LDFLAGS=", "CGO_ENABLED=", "CGO_CFLAGS=", "CGO_LDFLAGS=",
			"npm_config_", "NPM_CONFIG_",
			"BASH_ENV=", "ENV=", "BASH_FUNC_",
		},
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

	// 3. Reject env var assignments in command name (e.g., "FOO=bar cmd")
	if strings.Contains(cmd, "=") {
		return fmt.Errorf("command name contains '=': possible environment variable injection")
	}

	// 4. Check if command is in the allow list
	if len(v.allowList) > 0 {
		if !v.isAllowed(cmd) {
			return fmt.Errorf("command %q is not allowed", cmd)
		}
	}

	// 5. Check blocked subcommands (e.g., "go run", "npm exec")
	if err := v.validateSubcommands(cmd, args); err != nil {
		return err
	}

	// 6. Check args for obviously malicious patterns
	// NOTE: We do NOT check for shell metacharacters (|, $, >, etc.) because
	// exec.Command treats them as literal strings, not shell operators
	for i, arg := range args {
		if err := v.validateArgument(arg); err != nil {
			return fmt.Errorf("argument %d is unsafe: %w", i, err)
		}
	}

	return nil
}

// maxArgLength is the maximum allowed argument length (10 KB).
// Prevents DoS via extremely long arguments.
const maxArgLength = 10_000

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
		return fmt.Errorf("command name contains shell metacharacter: %q", string(cmd[i]))
	}

	return nil
}

// isAllowed checks if the command name is in the allow list.
func (v *Command) isAllowed(cmd string) bool {
	cmdTrimmed := strings.TrimSpace(cmd)
	for _, allowed := range v.allowList {
		if strings.EqualFold(cmdTrimmed, allowed) {
			return true
		}
	}
	return false
}

// validateSubcommands enforces the subcommand allowlist and blocked argument patterns.
//
// Default-deny: if a command has an allowedSubcommands entry, only those subcommands
// are permitted. Any subcommand not in the list is blocked. Commands without an
// allowedSubcommands entry skip this check (e.g., "ls" has no subcommands).
//
// Additionally, blockedArgPatterns are checked at EVERY argument position to prevent
// flag-based bypass (e.g., "git -c alias.x=!cmd" where -c appears before the subcommand).
func (v *Command) validateSubcommands(cmd string, args []string) error {
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))

	// Check blocked argument patterns FIRST (any position).
	// This catches flag-based bypass like "git -c alias.x=!cmd status"
	// where the dangerous flag appears before the subcommand.
	if blocked, ok := v.blockedArgPatterns[cmdLower]; ok {
		for _, arg := range args {
			argLower := strings.ToLower(strings.TrimSpace(arg))
			for _, pattern := range blocked {
				// Match exact or flag=value form (e.g., "--eval" matches "--eval=cmd")
				if argLower == pattern || strings.HasPrefix(argLower, pattern+"=") {
					return fmt.Errorf("argument %q is not allowed with %q", arg, cmd)
				}
			}
		}
	}

	// Check allowed subcommands (default-deny).
	// If the command has an allowlist, the first argument MUST be in it.
	if allowed, ok := v.allowedSubcommands[cmdLower]; ok {
		if len(args) == 0 {
			return fmt.Errorf("%q requires a subcommand", cmd)
		}
		firstArg := strings.ToLower(strings.TrimSpace(args[0]))
		if !slices.Contains(allowed, firstArg) {
			return fmt.Errorf("subcommand %q is not allowed for %q", args[0], cmd)
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
//   - Embedded dangerous commands (e.g., "rm -rf /")
//   - Null bytes
//   - Extremely long arguments (possible buffer overflow)
//   - Environment variable assignments that influence build tools
func (v *Command) validateArgument(arg string) error {
	// Check for null bytes (often used in injection attacks)
	if strings.Contains(arg, "\x00") {
		return fmt.Errorf("argument contains null byte")
	}

	// Check for unreasonably long arguments (possible DoS or buffer overflow)
	if len(arg) > maxArgLength {
		return fmt.Errorf("argument too long (%d bytes, max %d)", len(arg), maxArgLength)
	}

	// Check for embedded dangerous command patterns
	// These are suspicious even in arguments
	argLower := strings.ToLower(arg)
	for _, pattern := range dangerousArgPatterns {
		if strings.Contains(argLower, pattern) {
			return fmt.Errorf("argument contains dangerous pattern: %s", pattern)
		}
	}

	// Check for blocked environment variable prefixes in arguments.
	// Blocks patterns like "GOFLAGS=-buildmode=..." or "npm_config_script_shell=..."
	for _, prefix := range v.blockedEnvPrefixes {
		if strings.HasPrefix(argLower, strings.ToLower(prefix)) {
			return fmt.Errorf("argument contains blocked environment variable: %s", prefix)
		}
	}

	return nil
}
