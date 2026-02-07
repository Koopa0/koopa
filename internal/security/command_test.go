package security

import (
	"testing"
)

// TestCommandValidation tests command validation
func TestCommandValidation(t *testing.T) {
	cmdValidator := NewCommand()

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
			name:      "legitimate go build with ldflags",
			command:   "go",
			args:      []string{"build", "-ldflags=-X main.version=$VERSION"},
			shouldErr: false,
			reason:    "legitimate go build command with $ in args should be allowed (exec.Command treats $ as literal)",
		},
		{
			name:      "safe pipe character in argument",
			command:   "echo",
			args:      []string{"file | not-a-shell-command"},
			shouldErr: false,
			reason:    "pipe in argument is safe with exec.Command (treated as literal string)",
		},
		{
			name:      "safe backticks in argument",
			command:   "echo",
			args:      []string{"`whoami`"},
			shouldErr: false,
			reason:    "backticks in argument are safe with exec.Command (treated as literal string)",
		},
		{
			name:      "safe $() in argument",
			command:   "echo",
			args:      []string{"$(whoami)"},
			shouldErr: false,
			reason:    "command substitution in argument is safe with exec.Command (treated as literal string)",
		},
		{
			name:      "embedded dangerous command pattern in arg",
			command:   "echo",
			args:      []string{"rm -rf /"},
			shouldErr: true,
			reason:    "embedded dangerous command pattern should be blocked",
		},
		{
			name:      "null byte in argument",
			command:   "echo",
			args:      []string{"hello\x00world"},
			shouldErr: true,
			reason:    "null byte in argument should be blocked (injection attack)",
		},
		{
			name:      "extremely long argument",
			command:   "echo",
			args:      []string{string(make([]byte, 20000))},
			shouldErr: true,
			reason:    "extremely long argument should be blocked (DoS risk)",
		},
		{
			name:      "rm command blocked by whitelist",
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
			err := cmdValidator.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %q, but got none: %s", tt.command, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %q: %v (%s)", tt.command, err, tt.reason)
			}
		})
	}
}

// TestStrictCommandValidator tests command validator (whitelist mode)
// NOTE: NewCommand() now uses whitelist mode by default for security
func TestStrictCommandValidator(t *testing.T) {
	validator := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		{
			name:      "allowed command - ls",
			command:   "ls",
			args:      []string{"-la"},
			shouldErr: false,
		},
		{
			name:      "allowed command - git status",
			command:   "git",
			args:      []string{"status"},
			shouldErr: false,
		},
		{
			name:      "disallowed command - rm",
			command:   "rm",
			args:      []string{"-rf", "/"},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %q", tt.command)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.command, err)
			}
		})
	}
}

// TestBlockedSubcommands tests that whitelisted commands with dangerous
// subcommands are blocked (e.g., "go run", "npm exec", "find -exec").
func TestBlockedSubcommands(t *testing.T) {
	v := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
	}{
		// go: allowed subcommands
		{name: "go build allowed", command: "go", args: []string{"build", "./..."}, shouldErr: false},
		{name: "go test allowed", command: "go", args: []string{"test", "-race", "./..."}, shouldErr: false},
		{name: "go vet allowed", command: "go", args: []string{"vet", "./..."}, shouldErr: false},
		{name: "go mod tidy allowed", command: "go", args: []string{"mod", "tidy"}, shouldErr: false},
		{name: "go version allowed", command: "go", args: []string{"version"}, shouldErr: false},
		// go: blocked subcommands
		{name: "go run blocked", command: "go", args: []string{"run", "main.go"}, shouldErr: true},
		{name: "go generate blocked", command: "go", args: []string{"generate", "./..."}, shouldErr: true},
		{name: "go tool blocked", command: "go", args: []string{"tool", "compile"}, shouldErr: true},
		// npm: blocked subcommands
		{name: "npm run blocked", command: "npm", args: []string{"run", "build"}, shouldErr: true},
		{name: "npm exec blocked", command: "npm", args: []string{"exec", "evilpkg"}, shouldErr: true},
		{name: "npm start blocked", command: "npm", args: []string{"start"}, shouldErr: true},
		// npm: allowed subcommands
		{name: "npm list allowed", command: "npm", args: []string{"list"}, shouldErr: false},
		{name: "npm audit allowed", command: "npm", args: []string{"audit"}, shouldErr: false},
		// yarn: blocked subcommands
		{name: "yarn run blocked", command: "yarn", args: []string{"run", "dev"}, shouldErr: true},
		{name: "yarn exec blocked", command: "yarn", args: []string{"exec", "something"}, shouldErr: true},
		// git: blocked subcommands
		{name: "git status allowed", command: "git", args: []string{"status"}, shouldErr: false},
		{name: "git log allowed", command: "git", args: []string{"log", "--oneline"}, shouldErr: false},
		{name: "git diff allowed", command: "git", args: []string{"diff"}, shouldErr: false},
		{name: "git filter-branch blocked", command: "git", args: []string{"filter-branch", "--tree-filter", "cmd"}, shouldErr: true},
		{name: "git config blocked", command: "git", args: []string{"config", "alias.evil", "!evil"}, shouldErr: true},
		{name: "git difftool blocked", command: "git", args: []string{"difftool"}, shouldErr: true},
		{name: "git mergetool blocked", command: "git", args: []string{"mergetool"}, shouldErr: true},
		// Removed commands: now blocked by whitelist
		{name: "cat removed from whitelist", command: "cat", args: []string{"file.txt"}, shouldErr: true},
		{name: "grep removed from whitelist", command: "grep", args: []string{"pattern", "file.txt"}, shouldErr: true},
		{name: "find removed from whitelist", command: "find", args: []string{".", "-name", "*.go"}, shouldErr: true},
		{name: "make removed from whitelist", command: "make", args: []string{"build"}, shouldErr: true},
		{name: "mkdir removed from whitelist", command: "mkdir", args: []string{"newdir"}, shouldErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("ValidateCommand(%q, %v) = nil, want error", tt.command, tt.args)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("ValidateCommand(%q, %v) = %v, want nil", tt.command, tt.args, err)
			}
		})
	}
}

// TestCommandValidationEdgeCases tests edge cases in command validation
func TestCommandValidationEdgeCases(t *testing.T) {
	cmdValidator := NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
		reason    string
	}{
		{
			name:      "args with && operator but no dangerous pattern",
			command:   "echo",
			args:      []string{"pattern", "&&", "file.txt"},
			shouldErr: false,
			reason:    "&& in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args with || operator but no dangerous pattern",
			command:   "echo",
			args:      []string{"pattern", "||", "file.txt"},
			shouldErr: false,
			reason:    "|| in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args containing dangerous pattern with newline",
			command:   "echo",
			args:      []string{"hello\nrm -rf /"},
			shouldErr: true,
			reason:    "embedded dangerous pattern 'rm -rf /' should be blocked even with newline",
		},
		{
			name:      "safe args only",
			command:   "ls",
			args:      []string{"-la"},
			shouldErr: false,
			reason:    "safe command with safe args should be allowed",
		},
		{
			name:      "args with redirection characters",
			command:   "echo",
			args:      []string{"output > file.txt"},
			shouldErr: false,
			reason:    "redirection in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args with semicolon but no dangerous pattern",
			command:   "echo",
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
			err := cmdValidator.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %q, but got none: %s", tt.name, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %q: %v (%s)", tt.name, err, tt.reason)
			}
		})
	}
}
