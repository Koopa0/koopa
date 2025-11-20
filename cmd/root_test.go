package cmd

import (
	"os"
	"testing"

	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/spf13/cobra"
)

// ============================================================================
// NewRootCmd Tests
// ============================================================================

func TestNewRootCmd(t *testing.T) {
	cfg := &config.Config{
		ModelName: "gemini-2.0-flash-exp",
	}

	cmd := NewRootCmd(cfg)

	// Verify command properties
	if cmd == nil {
		t.Fatal("expected non-nil command")
		return
	}

	if cmd.Use != "koopa" {
		t.Errorf("expected Use=%q, got %q", "koopa", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}

	if cmd.PersistentPreRunE == nil {
		t.Error("expected non-nil PersistentPreRunE")
	}

	// Verify strings in descriptions
	expectedStrings := []string{
		"terminal",
		"AI",
		"assistant",
	}

	for _, expected := range expectedStrings {
		found := false
		if containsString(cmd.Short, expected) || containsString(cmd.Long, expected) {
			found = true
		}
		if !found {
			t.Errorf("expected description to contain %q", expected)
		}
	}
}

// ============================================================================
// PersistentPreRunE Tests (API Key Validation)
// ============================================================================

func TestRootCmd_PersistentPreRunE_APIKeyValidation(t *testing.T) {
	cfg := &config.Config{
		ModelName: "gemini-2.0-flash-exp",
	}

	tests := []struct {
		name           string
		requiresAPIKey bool
		setupEnv       func()
		cleanupEnv     func()
		expectError    bool
		errorContains  string
	}{
		{
			name:           "command requires API key - key is set",
			requiresAPIKey: true,
			setupEnv: func() {
				_ = os.Setenv("GEMINI_API_KEY", "test-key-123")
			},
			cleanupEnv: func() {
				// No-op, restoration handled by test wrapper
			},
			expectError: false,
		},
		{
			name:           "command requires API key - key not set",
			requiresAPIKey: true,
			setupEnv: func() {
				_ = os.Unsetenv("GEMINI_API_KEY")
			},
			cleanupEnv:    func() {},
			expectError:   true,
			errorContains: "GEMINI_API_KEY not set",
		},
		{
			name:           "command does not require API key - key not set",
			requiresAPIKey: false,
			setupEnv: func() {
				if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
					t.Fatalf("Failed to unset GEMINI_API_KEY: %v", err)
				}
			},
			cleanupEnv:  func() {},
			expectError: false,
		},
		{
			name:           "command does not require API key - key is set",
			requiresAPIKey: false,
			setupEnv: func() {
				_ = os.Setenv("GEMINI_API_KEY", "test-key-456")
			},
			cleanupEnv: func() {
				// No-op
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env
			originalKey := os.Getenv("GEMINI_API_KEY")
			defer func() {
				if err := os.Setenv("GEMINI_API_KEY", originalKey); err != nil {
					t.Errorf("Failed to restore GEMINI_API_KEY: %v", err)
				}
			}()

			// Setup environment
			tt.setupEnv()
			// defer tt.cleanupEnv() // Removed as restoration is handled above

			// Create root command
			rootCmd := NewRootCmd(cfg)

			// Create a mock subcommand
			mockCmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil
				},
			}

			if tt.requiresAPIKey {
				mockCmd.Annotations = map[string]string{
					"requiresAPIKey": "true",
				}
			}

			rootCmd.AddCommand(mockCmd)

			// Test PersistentPreRunE
			err := rootCmd.PersistentPreRunE(mockCmd, []string{})

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errorContains != "" {
					if !containsString(err.Error(), tt.errorContains) {
						t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// PersistentPreRunE Edge Cases
// ============================================================================

func TestRootCmd_PersistentPreRunE_EdgeCases(t *testing.T) {
	cfg := &config.Config{
		ModelName: "gemini-2.0-flash-exp",
	}

	tests := []struct {
		name        string
		setupCmd    func() *cobra.Command
		setupEnv    func()
		cleanupEnv  func()
		expectError bool
	}{
		{
			name: "command with nil annotations",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{
					Use:         "test",
					Annotations: nil,
				}
			},
			setupEnv:    func() {},
			cleanupEnv:  func() {},
			expectError: false,
		},
		{
			name: "command with empty annotations",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{
					Use:         "test",
					Annotations: map[string]string{},
				}
			},
			setupEnv:    func() {},
			cleanupEnv:  func() {},
			expectError: false,
		},
		{
			name: "command with false requiresAPIKey",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{
					Use: "test",
					Annotations: map[string]string{
						"requiresAPIKey": "false",
					},
				}
			},
			setupEnv:    func() {},
			cleanupEnv:  func() {},
			expectError: false,
		},
		{
			name: "empty GEMINI_API_KEY env var",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{
					Use: "test",
					Annotations: map[string]string{
						"requiresAPIKey": "true",
					},
				}
			},
			setupEnv: func() {
				if err := os.Setenv("GEMINI_API_KEY", ""); err != nil {
					t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
				}
			},
			cleanupEnv: func() {
				if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
					t.Fatalf("Failed to unset GEMINI_API_KEY: %v", err)
				}
			},
			expectError: true,
		},
		{
			name: "whitespace-only GEMINI_API_KEY",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{
					Use: "test",
					Annotations: map[string]string{
						"requiresAPIKey": "true",
					},
				}
			},
			setupEnv: func() {
				if err := os.Setenv("GEMINI_API_KEY", "   "); err != nil {
					t.Fatalf("Failed to set GEMINI_API_KEY: %v", err)
				}
			},
			cleanupEnv: func() {
				if err := os.Unsetenv("GEMINI_API_KEY"); err != nil {
					t.Fatalf("Failed to unset GEMINI_API_KEY: %v", err)
				}
			},
			expectError: false, // os.Getenv doesn't trim, treats as non-empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env
			originalKey := os.Getenv("GEMINI_API_KEY")
			defer func() {
				if err := os.Setenv("GEMINI_API_KEY", originalKey); err != nil {
					t.Errorf("Failed to restore GEMINI_API_KEY: %v", err)
				}
			}()

			tt.setupEnv()
			// defer tt.cleanupEnv()

			rootCmd := NewRootCmd(cfg)
			mockCmd := tt.setupCmd()

			err := rootCmd.PersistentPreRunE(mockCmd, []string{})

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestRootCmd_Integration(t *testing.T) {
	t.Run("root command with version subcommand", func(t *testing.T) {
		cfg := &config.Config{
			ModelName:   "gemini-2.0-flash-exp",
			Temperature: 0.7,
		}

		rootCmd := NewRootCmd(cfg)
		versionCmd := NewVersionCmd(cfg)
		rootCmd.AddCommand(versionCmd)

		// Verify subcommand is added
		if !rootCmd.HasSubCommands() {
			t.Error("expected root command to have subcommands")
		}

		// Find version command
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Use == "version" {
				found = true
				break
			}
		}

		if !found {
			t.Error("expected to find version subcommand")
		}
	})

	t.Run("multiple subcommands", func(t *testing.T) {
		cfg := &config.Config{
			ModelName: "gemini-2.0-flash-exp",
		}

		rootCmd := NewRootCmd(cfg)
		versionCmd := NewVersionCmd(cfg)

		// Add multiple commands
		rootCmd.AddCommand(versionCmd)

		if len(rootCmd.Commands()) < 1 {
			t.Error("expected at least 1 subcommand")
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
