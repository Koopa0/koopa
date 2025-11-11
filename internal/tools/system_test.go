package tools

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/security"
)

// TestSystemToolsRegistration tests that system tools are registered
func TestSystemToolsRegistration(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("registerSystemTools panicked: %v", r)
		}
	}()

	handler := NewHandler(nil, cmdVal, nil, envVal)
	registerSystemTools(g, handler)
}

// TestCurrentTimeFormat tests time formatting
func TestCurrentTimeFormat(t *testing.T) {
	now := time.Now()
	formatted := now.Format("2006-01-02 15:04:05 (Monday)")

	// Verify format contains expected components
	if !strings.Contains(formatted, "-") {
		t.Error("formatted time should contain date separators")
	}

	if !strings.Contains(formatted, ":") {
		t.Error("formatted time should contain time separators")
	}

	if !strings.Contains(formatted, "(") || !strings.Contains(formatted, ")") {
		t.Error("formatted time should contain day of week in parentheses")
	}
}

// TestCommandValidation tests command security validation
func TestCommandValidation(t *testing.T) {
	cmdVal := security.NewCommand()

	tests := []struct {
		name      string
		command   string
		args      []string
		shouldErr bool
		reason    string
	}{
		{
			name:      "safe command",
			command:   "echo",
			args:      []string{"hello"},
			shouldErr: false,
			reason:    "echo is a safe command",
		},
		{
			name:      "ls command",
			command:   "ls",
			args:      []string{"-la"},
			shouldErr: false,
			reason:    "ls is a safe command",
		},
		{
			name:      "dangerous rm -rf",
			command:   "rm",
			args:      []string{"-rf", "/"},
			shouldErr: true,
			reason:    "rm -rf should be blocked",
		},
		{
			name:      "sudo su blocked",
			command:   "sudo",
			args:      []string{"su"},
			shouldErr: true,
			reason:    "sudo su should be blocked",
		},
		{
			name:      "command injection attempt",
			command:   "ls",
			args:      []string{"; rm -rf /"},
			shouldErr: true,
			reason:    "command injection should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdVal.ValidateCommand(tt.command, tt.args)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %s %v (%s), got none",
					tt.command, tt.args, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %s %v: %v (%s)",
					tt.command, tt.args, err, tt.reason)
			}
		})
	}
}

// TestCommandExecution tests actual command execution
func TestCommandExecution(t *testing.T) {
	// Test safe command execution
	cmd := exec.Command("echo", "hello")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("safe command failed: %v", err)
	}

	if !strings.Contains(string(output), "hello") {
		t.Errorf("expected output to contain 'hello', got: %s", string(output))
	}
}

// TestEnvironmentVariableValidation tests env var security validation
func TestEnvironmentVariableValidation(t *testing.T) {
	envVal := security.NewEnv()

	tests := []struct {
		name      string
		envVar    string
		shouldErr bool
		reason    string
	}{
		{
			name:      "safe variable PATH",
			envVar:    "PATH",
			shouldErr: false,
			reason:    "PATH is a safe environment variable",
		},
		{
			name:      "safe variable HOME",
			envVar:    "HOME",
			shouldErr: false,
			reason:    "HOME is a safe environment variable",
		},
		{
			name:      "blocked API_KEY",
			envVar:    "API_KEY",
			shouldErr: true,
			reason:    "API_KEY should be blocked",
		},
		{
			name:      "blocked SECRET",
			envVar:    "MY_SECRET",
			shouldErr: true,
			reason:    "variables containing SECRET should be blocked",
		},
		{
			name:      "blocked TOKEN",
			envVar:    "AUTH_TOKEN",
			shouldErr: true,
			reason:    "variables containing TOKEN should be blocked",
		},
		{
			name:      "blocked PASSWORD",
			envVar:    "DB_PASSWORD",
			shouldErr: true,
			reason:    "variables containing PASSWORD should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := envVal.ValidateEnvAccess(tt.envVar)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error for %s (%s), got none", tt.envVar, tt.reason)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for %s: %v (%s)", tt.envVar, err, tt.reason)
			}
		})
	}
}

// TestEnvironmentVariableAccess tests reading env vars
func TestEnvironmentVariableAccess(t *testing.T) {
	// Set test environment variable
	testKey := "TEST_SAFE_VAR"
	testValue := "test value 123"

	os.Setenv(testKey, testValue)
	defer os.Unsetenv(testKey)

	// Read environment variable
	value := os.Getenv(testKey)
	if value != testValue {
		t.Errorf("expected %s, got %s", testValue, value)
	}

	// Test non-existent variable
	value = os.Getenv("NONEXISTENT_VAR_XYZ")
	if value != "" {
		t.Errorf("expected empty string for non-existent variable, got %s", value)
	}
}

// TestCommandWithMultipleArgs tests commands with multiple arguments
func TestCommandWithMultipleArgs(t *testing.T) {
	cmdVal := security.NewCommand()

	// Test git command with multiple args
	err := cmdVal.ValidateCommand("git", []string{"log", "--oneline", "-n", "5"})
	if err != nil {
		t.Errorf("git command should be allowed: %v", err)
	}

	// Test go command with multiple args
	err = cmdVal.ValidateCommand("go", []string{"build", "-o", "output", "./..."})
	if err != nil {
		t.Errorf("go build command should be allowed: %v", err)
	}
}

// TestDangerousCommandBlocking tests that dangerous commands are blocked
func TestDangerousCommandBlocking(t *testing.T) {
	cmdVal := security.NewCommand()

	dangerousCommands := []struct {
		command string
		args    []string
	}{
		{"rm", []string{"-rf", "/"}},
		{"dd", []string{"if=/dev/zero", "of=/dev/sda"}},
		{"mkfs", []string{"/dev/sda1"}},
		{"shutdown", []string{"-h", "now"}},
		{"reboot", []string{}},
		{"halt", []string{}},
	}

	for _, dc := range dangerousCommands {
		err := cmdVal.ValidateCommand(dc.command, dc.args)
		if err == nil {
			t.Errorf("dangerous command %s %v should be blocked",
				dc.command, dc.args)
		}
	}
}

// TestTimeConsistency tests that time operations are consistent
func TestTimeConsistency(t *testing.T) {
	time1 := time.Now()
	time.Sleep(10 * time.Millisecond)
	time2 := time.Now()

	if !time2.After(time1) {
		t.Error("time2 should be after time1")
	}

	duration := time2.Sub(time1)
	if duration < 10*time.Millisecond {
		t.Errorf("duration should be at least 10ms, got %v", duration)
	}
}

// TestCommandOutputHandling tests handling of command output
func TestCommandOutputHandling(t *testing.T) {
	// Test command with output
	cmd := exec.Command("echo", "test output")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr != "test output" {
		t.Errorf("expected 'test output', got %q", outputStr)
	}

	// Test command with stderr
	cmd = exec.Command("sh", "-c", "echo 'stderr message' >&2")
	output, err = cmd.CombinedOutput()
	// Command should succeed
	if err != nil {
		t.Logf("command returned error (may be platform-specific): %v", err)
	}

	if len(output) == 0 {
		t.Error("expected output from stderr")
	}
}

// BenchmarkCommandValidation benchmarks command validation
func BenchmarkCommandValidation(b *testing.B) {
	cmdVal := security.NewCommand()
	command := "ls"
	args := []string{"-la", "/tmp"}

	b.ResetTimer()
	for b.Loop() {
		_ = cmdVal.ValidateCommand(command, args)
	}
}

// BenchmarkEnvValidation benchmarks environment variable validation
func BenchmarkEnvValidation(b *testing.B) {
	envVal := security.NewEnv()
	envVar := "PATH"

	b.ResetTimer()
	for b.Loop() {
		_ = envVal.ValidateEnvAccess(envVar)
	}
}
