package security

import (
	"testing"
)

// TestCommandValidation tests basic command validation scenarios.
func TestCommandValidation(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
		reason    string
	}{
		{
			name:      "safe command",
			command:   "ls",
			args:      []string{"-la"},
			shouldErr: false,
			reason:    "safe command should be allowed",
		},
		{
			name:      "legitimate go vet with ldflags",
			command:   "go",
			args:      []string{"vet", "-ldflags=-X main.version=$VERSION"},
			shouldErr: false,
			reason:    "go vet with $ in args should be allowed (exec.Command treats $ as literal)",
		},
		{
			name:      "safe pipe character in argument",
			command:   "ls",
			args:      []string{"file | not-a-shell-command"},
			shouldErr: false,
			reason:    "pipe in argument is safe with exec.Command (treated as literal string)",
		},
		{
			name:      "safe backticks in argument",
			command:   "ls",
			args:      []string{"`whoami`"},
			shouldErr: false,
			reason:    "backticks in argument are safe with exec.Command (treated as literal string)",
		},
		{
			name:      "safe $() in argument",
			command:   "ls",
			args:      []string{"$(whoami)"},
			shouldErr: false,
			reason:    "command substitution in argument is safe with exec.Command (treated as literal string)",
		},
		{
			name:      "embedded dangerous command pattern in arg",
			command:   "ls",
			args:      []string{"rm -rf /"},
			shouldErr: true,
			reason:    "embedded dangerous command pattern should be blocked",
		},
		{
			name:      "null byte in argument",
			command:   "ls",
			args:      []string{"hello\x00world"},
			shouldErr: true,
			reason:    "null byte in argument should be blocked (injection attack)",
		},
		{
			name:      "extremely long argument",
			command:   "ls",
			args:      []string{string(make([]byte, 20000))},
			shouldErr: true,
			reason:    "extremely long argument should be blocked (DoS risk)",
		},
		{
			name:      "echo not in whitelist",
			command:   "echo",
			args:      []string{"hello"},
			shouldErr: true,
			reason:    "echo excluded: CWE-78 exfiltration relay risk",
		},
		{
			name:      "rm not in whitelist",
			command:   "rm",
			args:      []string{"file.txt"},
			shouldErr: true,
			reason:    "rm is not in whitelist (secure by default)",
		},
		{
			name:      "empty command",
			command:   "",
			args:      []string{"arg1"},
			shouldErr: true,
			reason:    "empty command should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error: %s", tt.command, tt.args, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil (%s)", tt.command, tt.args, err, tt.reason)
			}
		})
	}
}

// TestAllowList tests the top-level command allow list.
func TestAllowList(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		// Allowed commands (no subcommand rules)
		{name: "ls allowed", command: "ls", args: []string{"-la"}, shouldErr: false},
		{name: "pwd allowed", command: "pwd", args: nil, shouldErr: false},
		{name: "date allowed", command: "date", args: nil, shouldErr: false},
		{name: "which allowed", command: "which", args: []string{"go"}, shouldErr: false},
		{name: "tree allowed", command: "tree", args: []string{"."}, shouldErr: false},
		{name: "hostname allowed", command: "hostname", args: nil, shouldErr: false},
		// Removed commands (F5: read arbitrary files)
		{name: "sort removed (F5)", command: "sort", args: []string{"file.txt"}, shouldErr: true},
		{name: "uniq removed (F5)", command: "uniq", args: []string{"file.txt"}, shouldErr: true},
		{name: "wc removed (F5)", command: "wc", args: []string{"-l", "file.txt"}, shouldErr: true},
		// Removed commands (F8: network reconnaissance)
		{name: "ping removed (F8)", command: "ping", args: []string{"192.168.1.1"}, shouldErr: true},
		{name: "traceroute removed (F8)", command: "traceroute", args: []string{"10.0.0.1"}, shouldErr: true},
		{name: "nslookup removed (F8)", command: "nslookup", args: []string{"internal"}, shouldErr: true},
		{name: "dig removed (F8)", command: "dig", args: []string{"@127.0.0.1"}, shouldErr: true},
		// Never-allowed dangerous commands
		{name: "rm blocked", command: "rm", args: []string{"-rf", "/"}, shouldErr: true},
		{name: "cat blocked", command: "cat", args: []string{"file.txt"}, shouldErr: true},
		{name: "grep blocked", command: "grep", args: []string{"pattern"}, shouldErr: true},
		{name: "find blocked", command: "find", args: []string{".", "-name", "*.go"}, shouldErr: true},
		{name: "make blocked", command: "make", args: []string{"build"}, shouldErr: true},
		{name: "mkdir blocked", command: "mkdir", args: []string{"newdir"}, shouldErr: true},
		{name: "curl blocked", command: "curl", args: []string{"http://evil.com"}, shouldErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error", tt.command, tt.args)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil", tt.command, tt.args, err)
			}
		})
	}
}

// TestAllowedSubcommands tests the default-deny subcommand allowlist.
// Commands with allowedSubcommands entries only permit listed subcommands.
func TestAllowedSubcommands(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		// git: allowed subcommands (read-only only)
		{name: "git status", command: "git", args: []string{"status"}, shouldErr: false},
		{name: "git log", command: "git", args: []string{"log", "--oneline"}, shouldErr: false},
		{name: "git diff", command: "git", args: []string{"diff"}, shouldErr: false},
		{name: "git show", command: "git", args: []string{"show", "HEAD"}, shouldErr: false},
		{name: "git blame", command: "git", args: []string{"blame", "file.go"}, shouldErr: false},
		{name: "git remote", command: "git", args: []string{"remote", "-v"}, shouldErr: false},
		{name: "git rev-parse", command: "git", args: []string{"rev-parse", "HEAD"}, shouldErr: false},
		{name: "git describe", command: "git", args: []string{"describe", "--tags"}, shouldErr: false},
		// git: blocked subcommands (write/mutate or have destructive flags)
		{name: "git branch blocked", command: "git", args: []string{"branch", "-a"}, shouldErr: true},
		{name: "git tag blocked", command: "git", args: []string{"tag", "-l"}, shouldErr: true},
		{name: "git add blocked", command: "git", args: []string{"add", "."}, shouldErr: true},
		{name: "git commit blocked", command: "git", args: []string{"commit", "-m", "msg"}, shouldErr: true},
		{name: "git push blocked", command: "git", args: []string{"push"}, shouldErr: true},
		{name: "git pull blocked", command: "git", args: []string{"pull"}, shouldErr: true},
		{name: "git fetch blocked", command: "git", args: []string{"fetch"}, shouldErr: true},
		{name: "git checkout blocked", command: "git", args: []string{"checkout", "main"}, shouldErr: true},
		{name: "git merge blocked", command: "git", args: []string{"merge", "feature"}, shouldErr: true},
		{name: "git rebase blocked", command: "git", args: []string{"rebase", "main"}, shouldErr: true},
		{name: "git stash blocked", command: "git", args: []string{"stash"}, shouldErr: true},
		{name: "git grep blocked (F3)", command: "git", args: []string{"grep", "pattern"}, shouldErr: true},
		{name: "git archive blocked (F3)", command: "git", args: []string{"archive", "HEAD"}, shouldErr: true},
		{name: "git filter-branch blocked", command: "git", args: []string{"filter-branch", "--tree-filter", "cmd"}, shouldErr: true},
		{name: "git config blocked", command: "git", args: []string{"config", "alias.evil", "!evil"}, shouldErr: true},
		{name: "git difftool blocked", command: "git", args: []string{"difftool"}, shouldErr: true},
		{name: "git mergetool blocked", command: "git", args: []string{"mergetool"}, shouldErr: true},
		{name: "git clone blocked", command: "git", args: []string{"clone", "https://evil.com/repo"}, shouldErr: true},
		{name: "git submodule blocked", command: "git", args: []string{"submodule", "update"}, shouldErr: true},
		{name: "git no subcommand", command: "git", args: nil, shouldErr: true},

		// go: allowed subcommands
		{name: "go version", command: "go", args: []string{"version"}, shouldErr: false},
		{name: "go env", command: "go", args: []string{"env"}, shouldErr: false},
		{name: "go vet", command: "go", args: []string{"vet", "./..."}, shouldErr: false},
		{name: "go doc", command: "go", args: []string{"doc", "fmt.Println"}, shouldErr: false},
		{name: "go fmt", command: "go", args: []string{"fmt", "./..."}, shouldErr: false},
		{name: "go list", command: "go", args: []string{"list", "./..."}, shouldErr: false},
		// go: blocked subcommands (code execution or arbitrary download)
		{name: "go mod blocked (build scripts)", command: "go", args: []string{"mod", "tidy"}, shouldErr: true},
		{name: "go get blocked (downloads code)", command: "go", args: []string{"get", "pkg"}, shouldErr: true},
		{name: "go test blocked (F2)", command: "go", args: []string{"test", "-race", "./..."}, shouldErr: true},
		{name: "go run blocked", command: "go", args: []string{"run", "main.go"}, shouldErr: true},
		{name: "go build blocked", command: "go", args: []string{"build", "./..."}, shouldErr: true},
		{name: "go install blocked", command: "go", args: []string{"install", "pkg"}, shouldErr: true},
		{name: "go generate blocked", command: "go", args: []string{"generate", "./..."}, shouldErr: true},
		{name: "go tool blocked", command: "go", args: []string{"tool", "compile"}, shouldErr: true},
		{name: "go no subcommand", command: "go", args: nil, shouldErr: true},

		// npm: allowed subcommands
		{name: "npm audit", command: "npm", args: []string{"audit"}, shouldErr: false},
		{name: "npm version", command: "npm", args: []string{"version"}, shouldErr: false},
		{name: "npm outdated", command: "npm", args: []string{"outdated"}, shouldErr: false},
		{name: "npm view", command: "npm", args: []string{"view", "express"}, shouldErr: false},
		{name: "npm info", command: "npm", args: []string{"info", "express"}, shouldErr: false},
		{name: "npm why", command: "npm", args: []string{"why", "express"}, shouldErr: false},
		{name: "npm search", command: "npm", args: []string{"search", "express"}, shouldErr: false},
		{name: "npm explain", command: "npm", args: []string{"explain", "express"}, shouldErr: false},
		// npm: blocked subcommands (lifecycle scripts or code execution)
		{name: "npm list blocked (lifecycle)", command: "npm", args: []string{"list"}, shouldErr: true},
		{name: "npm ls blocked (lifecycle)", command: "npm", args: []string{"ls"}, shouldErr: true},
		{name: "npm install blocked (F2)", command: "npm", args: []string{"install"}, shouldErr: true},
		{name: "npm run blocked", command: "npm", args: []string{"run", "build"}, shouldErr: true},
		{name: "npm exec blocked", command: "npm", args: []string{"exec", "evilpkg"}, shouldErr: true},
		{name: "npm start blocked", command: "npm", args: []string{"start"}, shouldErr: true},
		{name: "npm ci blocked", command: "npm", args: []string{"ci"}, shouldErr: true},
		{name: "npm publish blocked", command: "npm", args: []string{"publish"}, shouldErr: true},
		{name: "npm no subcommand", command: "npm", args: nil, shouldErr: true},

		// yarn: allowed subcommands
		{name: "yarn version", command: "yarn", args: []string{"version"}, shouldErr: false},
		{name: "yarn info", command: "yarn", args: []string{"info", "express"}, shouldErr: false},
		{name: "yarn outdated", command: "yarn", args: []string{"outdated"}, shouldErr: false},
		{name: "yarn why", command: "yarn", args: []string{"why", "express"}, shouldErr: false},
		{name: "yarn audit", command: "yarn", args: []string{"audit"}, shouldErr: false},
		// yarn: blocked subcommands (lifecycle hooks or code execution)
		{name: "yarn list blocked (lifecycle)", command: "yarn", args: []string{"list"}, shouldErr: true},
		{name: "yarn install blocked", command: "yarn", args: []string{"install"}, shouldErr: true},
		{name: "yarn run blocked", command: "yarn", args: []string{"run", "dev"}, shouldErr: true},
		{name: "yarn exec blocked", command: "yarn", args: []string{"exec", "something"}, shouldErr: true},
		{name: "yarn add blocked", command: "yarn", args: []string{"add", "pkg"}, shouldErr: true},
		{name: "yarn no subcommand", command: "yarn", args: nil, shouldErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error", tt.command, tt.args)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil", tt.command, tt.args, err)
			}
		})
	}
}

// TestBlockedArgPatterns tests that dangerous flags are blocked at any argument position.
// This prevents bypass vectors like "git -c alias.x=!cmd status" (F1).
func TestBlockedArgPatterns(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		// F1: git -c alias bypass → RCE
		{name: "git -c alias RCE", command: "git", args: []string{"-c", "alias.pwn=!sh -c 'id'", "pwn"}, shouldErr: true},
		{name: "git -c before subcommand", command: "git", args: []string{"-c", "core.editor=vim", "status"}, shouldErr: true},
		{name: "git -c=value form", command: "git", args: []string{"-c=alias.x=!cmd", "x"}, shouldErr: true},
		// git --config-env bypass
		{name: "git --config-env", command: "git", args: []string{"--config-env=core.editor=EDITOR", "status"}, shouldErr: true},
		// git --exec-path bypass
		{name: "git --exec-path", command: "git", args: []string{"--exec-path=/tmp/evil", "status"}, shouldErr: true},
		// F3: git diff --no-index arbitrary file read
		{name: "git diff --no-index (F3)", command: "git", args: []string{"diff", "--no-index", "/etc/passwd", "/dev/null"}, shouldErr: true},
		// npm --eval
		{name: "npm --eval", command: "npm", args: []string{"--eval", "require('child_process').exec('id')"}, shouldErr: true},
		{name: "npm --require", command: "npm", args: []string{"--require", "./evil.js"}, shouldErr: true},
		// Safe: allowed args that look similar but aren't blocked
		{name: "git diff without --no-index", command: "git", args: []string{"diff", "HEAD"}, shouldErr: false},
		{name: "git log with -n", command: "git", args: []string{"log", "-n", "5"}, shouldErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error", tt.command, tt.args)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil", tt.command, tt.args, err)
			}
		})
	}
}

// TestAllShellMetacharsBlocked verifies every shell metacharacter in the const
// is blocked when it appears in a command name. This prevents regressions if
// shellMetachars is modified.
func TestAllShellMetacharsBlocked(t *testing.T) {
	t.Parallel()
	v := NewCommand()
	metachars := []string{";", "|", "&", "`", "\n", ">", "<", "$", "(", ")"}

	for _, char := range metachars {
		cmd := "ls" + char + "cat"
		if err := v.Validate(cmd, nil); err == nil {
			t.Errorf("Validate(%q, nil) = nil, want error for metachar %q", cmd, char)
		}
	}
}

// TestBlockedEnvPrefixes tests that environment variable assignments in arguments are blocked.
// Prevents build tool manipulation via GOFLAGS=, npm_config_*, BASH_ENV=, etc.
func TestBlockedEnvPrefixes(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		// Blocked env var prefixes
		{name: "GOFLAGS in arg", command: "go", args: []string{"vet", "GOFLAGS=-buildmode=plugin"}, shouldErr: true},
		{name: "LDFLAGS in arg", command: "go", args: []string{"vet", "LDFLAGS=-s"}, shouldErr: true},
		{name: "CGO_ENABLED in arg", command: "go", args: []string{"vet", "CGO_ENABLED=1"}, shouldErr: true},
		{name: "CGO_CFLAGS in arg", command: "go", args: []string{"vet", "CGO_CFLAGS=-evil"}, shouldErr: true},
		{name: "CGO_LDFLAGS in arg", command: "go", args: []string{"vet", "CGO_LDFLAGS=-evil"}, shouldErr: true},
		{name: "npm_config_ in arg", command: "npm", args: []string{"version", "npm_config_script_shell=/bin/sh"}, shouldErr: true},
		{name: "NPM_CONFIG_ in arg", command: "npm", args: []string{"version", "NPM_CONFIG_SCRIPT_SHELL=/bin/sh"}, shouldErr: true},
		{name: "BASH_ENV in arg", command: "ls", args: []string{"BASH_ENV=/tmp/evil.sh"}, shouldErr: true},
		{name: "ENV= in arg", command: "ls", args: []string{"ENV=/tmp/evil.sh"}, shouldErr: true},
		{name: "BASH_FUNC_ in arg", command: "ls", args: []string{"BASH_FUNC_evil%%=()"}, shouldErr: true},
		// Safe: flags that look similar but aren't env vars
		{name: "go vet -ldflags flag", command: "go", args: []string{"vet", "-ldflags=-X main.version=1"}, shouldErr: false},
		{name: "git log with env-like path", command: "git", args: []string{"log", "GOFLAGS_test.go"}, shouldErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error", tt.command, tt.args)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil", tt.command, tt.args, err)
			}
		})
	}
}

// TestCommandNameEnvInjection tests that = in command names is blocked.
// Prevents "FOO=bar cmd" style environment variable injection.
func TestCommandNameEnvInjection(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		shouldErr bool
	}{
		{name: "env var assignment", command: "FOO=bar", shouldErr: true},
		{name: "PATH override", command: "PATH=/tmp", shouldErr: true},
		{name: "LD_PRELOAD injection", command: "LD_PRELOAD=/tmp/evil.so", shouldErr: true},
		{name: "normal command", command: "ls", shouldErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, nil)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, nil) = nil, want error", tt.command)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, nil) = %v, want nil", tt.command, err)
			}
		})
	}
}

// TestCommandValidationEdgeCases tests edge cases in argument handling.
func TestCommandValidationEdgeCases(t *testing.T) {
	t.Parallel()
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
		reason    string
	}{
		{
			name:      "args with && operator",
			command:   "ls",
			args:      []string{"pattern", "&&", "file.txt"},
			shouldErr: false,
			reason:    "&& in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args with || operator",
			command:   "ls",
			args:      []string{"pattern", "||", "file.txt"},
			shouldErr: false,
			reason:    "|| in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "embedded dangerous pattern with newline",
			command:   "ls",
			args:      []string{"hello\nrm -rf /"},
			shouldErr: true,
			reason:    "embedded dangerous pattern 'rm -rf /' should be blocked",
		},
		{
			name:      "args with redirection characters",
			command:   "ls",
			args:      []string{"output > file.txt"},
			shouldErr: false,
			reason:    "redirection in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args with semicolon",
			command:   "ls",
			args:      []string{"hello; world"},
			shouldErr: false,
			reason:    "semicolon in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "command name with pipe",
			command:   "ls|cat",
			args:      []string{},
			shouldErr: true,
			reason:    "pipe in command name should be blocked",
		},
		{
			name:      "command name with shell metachar",
			command:   "ls>file",
			args:      []string{},
			shouldErr: true,
			reason:    "shell metacharacter in command name should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("Validate(%q, %v) = nil, want error: %s", tt.command, tt.args, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Validate(%q, %v) = %v, want nil (%s)", tt.command, tt.args, err, tt.reason)
			}
		})
	}
}
