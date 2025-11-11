package mcp

import (
	"os"
	"reflect"
	"testing"

	"github.com/koopa0/koopa-cli/internal/config"
)

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestEnvMapToSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected []string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: []string{},
		},
		{
			name: "single entry",
			input: map[string]string{
				"API_KEY": "secret123",
			},
			expected: []string{"API_KEY=secret123"},
		},
		{
			name: "multiple entries",
			input: map[string]string{
				"API_KEY": "secret123",
				"HOST":    "localhost",
				"PORT":    "8080",
			},
			expected: []string{"API_KEY=secret123", "HOST=localhost", "PORT=8080"},
		},
		{
			name: "empty values",
			input: map[string]string{
				"EMPTY": "",
				"KEY":   "value",
			},
			expected: []string{"EMPTY=", "KEY=value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := envMapToSlice(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			// Convert to map for order-independent comparison
			resultMap := make(map[string]bool)
			for _, item := range result {
				resultMap[item] = true
			}

			for _, expected := range tt.expected {
				if !resultMap[expected] {
					t.Errorf("expected to find %q in result", expected)
				}
			}
		})
	}
}

func TestResolveEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		envSetup map[string]string // Environment variables to set before test
		expected map[string]string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "literal values only",
			input: map[string]string{
				"API_KEY": "literal_secret",
				"HOST":    "example.com",
			},
			expected: map[string]string{
				"API_KEY": "literal_secret",
				"HOST":    "example.com",
			},
		},
		{
			name: "single env var reference",
			input: map[string]string{
				"API_KEY": "$TEST_API_KEY",
			},
			envSetup: map[string]string{
				"TEST_API_KEY": "resolved_secret",
			},
			expected: map[string]string{
				"API_KEY": "resolved_secret",
			},
		},
		{
			name: "mixed literal and env vars",
			input: map[string]string{
				"API_KEY": "$TEST_API_KEY",
				"HOST":    "localhost",
				"TOKEN":   "$TEST_TOKEN",
			},
			envSetup: map[string]string{
				"TEST_API_KEY": "key123",
				"TEST_TOKEN":   "token456",
			},
			expected: map[string]string{
				"API_KEY": "key123",
				"HOST":    "localhost",
				"TOKEN":   "token456",
			},
		},
		{
			name: "unset env var",
			input: map[string]string{
				"API_KEY": "$NONEXISTENT_VAR",
			},
			expected: map[string]string{
				"API_KEY": "", // Empty string for unset vars
			},
		},
		{
			name: "dollar sign at start but not env var",
			input: map[string]string{
				"WEIRD": "$",
			},
			expected: map[string]string{
				"WEIRD": "", // Treated as env var reference to ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variables
			if tt.envSetup != nil {
				for key, value := range tt.envSetup {
					os.Setenv(key, value)
				}
			}

			// Cleanup after test
			defer func() {
				if tt.envSetup != nil {
					for key := range tt.envSetup {
						os.Unsetenv(key)
					}
				}
			}()

			result := resolveEnvVars(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// ============================================================================
// Filter Function Tests
// ============================================================================

func TestFilterExcluded(t *testing.T) {
	tests := []struct {
		name       string
		candidates []Config
		excluded   []string
		expected   int // Expected number of remaining configs
	}{
		{
			name:       "empty excluded list",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			excluded:   []string{},
			expected:   2,
		},
		{
			name:       "nil excluded list",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			excluded:   nil,
			expected:   2,
		},
		{
			name:       "exclude one server",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}, {Name: "server3"}},
			excluded:   []string{"server2"},
			expected:   2,
		},
		{
			name:       "exclude multiple servers",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}, {Name: "server3"}},
			excluded:   []string{"server1", "server3"},
			expected:   1,
		},
		{
			name:       "exclude all servers",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			excluded:   []string{"server1", "server2"},
			expected:   0,
		},
		{
			name:       "exclude non-existent server",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			excluded:   []string{"nonexistent"},
			expected:   2,
		},
		{
			name:       "empty candidates",
			candidates: []Config{},
			excluded:   []string{"server1"},
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterExcluded(tt.candidates, tt.excluded)

			if len(result) != tt.expected {
				t.Errorf("expected %d configs after filtering, got %d", tt.expected, len(result))
			}

			// Verify excluded servers are not in result
			for _, cfg := range result {
				for _, excluded := range tt.excluded {
					if cfg.Name == excluded {
						t.Errorf("excluded server %q found in result", excluded)
					}
				}
			}
		})
	}
}

func TestFilterAllowed(t *testing.T) {
	tests := []struct {
		name       string
		candidates []Config
		allowed    []string
		expected   int // Expected number of remaining configs
	}{
		{
			name:       "empty allowed list",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			allowed:    []string{},
			expected:   2, // Empty allowed list means keep all
		},
		{
			name:       "nil allowed list",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			allowed:    nil,
			expected:   2, // Nil allowed list means keep all
		},
		{
			name:       "allow one server",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}, {Name: "server3"}},
			allowed:    []string{"server2"},
			expected:   1,
		},
		{
			name:       "allow multiple servers",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}, {Name: "server3"}},
			allowed:    []string{"server1", "server3"},
			expected:   2,
		},
		{
			name:       "allow all servers",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			allowed:    []string{"server1", "server2"},
			expected:   2,
		},
		{
			name:       "allow non-existent server",
			candidates: []Config{{Name: "server1"}, {Name: "server2"}},
			allowed:    []string{"nonexistent"},
			expected:   0,
		},
		{
			name:       "empty candidates",
			candidates: []Config{},
			allowed:    []string{"server1"},
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterAllowed(tt.candidates, tt.allowed)

			if len(result) != tt.expected {
				t.Errorf("expected %d configs after filtering, got %d", tt.expected, len(result))
			}

			// If allowed list is not empty, verify only allowed servers are in result
			if len(tt.allowed) > 0 {
				allowedSet := make(map[string]bool)
				for _, name := range tt.allowed {
					allowedSet[name] = true
				}

				for _, cfg := range result {
					if !allowedSet[cfg.Name] {
						t.Errorf("non-allowed server %q found in result", cfg.Name)
					}
				}
			}
		})
	}
}

// ============================================================================
// LoadConfigs Tests
// ============================================================================

func TestLoadConfigs(t *testing.T) {
	tests := []struct {
		name          string
		config        *config.Config
		envSetup      map[string]string
		expectedCount int
		shouldError   bool
	}{
		{
			name: "no servers configured",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{},
			},
			expectedCount: 0,
			shouldError:   false,
		},
		{
			name: "single valid server",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {
						Command: "npx",
						Args:    []string{"-y", "@modelcontextprotocol/server-github"},
					},
				},
			},
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name: "multiple valid servers",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {
						Command: "npx",
						Args:    []string{"-y", "@modelcontextprotocol/server-github"},
					},
					"notion": {
						Command: "npx",
						Args:    []string{"-y", "@notionhq/server-notion"},
					},
				},
			},
			expectedCount: 2,
			shouldError:   false,
		},
		{
			name: "server with missing command (should skip)",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"invalid": {
						Command: "", // Missing command
						Args:    []string{"arg1"},
					},
					"valid": {
						Command: "npx",
						Args:    []string{"-y", "server"},
					},
				},
			},
			expectedCount: 1, // Only valid server
			shouldError:   false,
		},
		{
			name: "server with env vars",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {
						Command: "npx",
						Args:    []string{"-y", "server"},
						Env: map[string]string{
							"API_KEY": "$TEST_GITHUB_TOKEN",
						},
					},
				},
			},
			envSetup: map[string]string{
				"TEST_GITHUB_TOKEN": "test_token_123",
			},
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name: "with excluded filter",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {Command: "npx", Args: []string{"server1"}},
					"notion": {Command: "npx", Args: []string{"server2"}},
					"slack":  {Command: "npx", Args: []string{"server3"}},
				},
				MCP: config.MCPConfig{
					Excluded: []string{"notion"},
				},
			},
			expectedCount: 2, // github and slack
			shouldError:   false,
		},
		{
			name: "with allowed filter",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {Command: "npx", Args: []string{"server1"}},
					"notion": {Command: "npx", Args: []string{"server2"}},
					"slack":  {Command: "npx", Args: []string{"server3"}},
				},
				MCP: config.MCPConfig{
					Allowed: []string{"github", "slack"},
				},
			},
			expectedCount: 2, // Only github and slack
			shouldError:   false,
		},
		{
			name: "excluded takes precedence over allowed",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {Command: "npx", Args: []string{"server1"}},
					"notion": {Command: "npx", Args: []string{"server2"}},
					"slack":  {Command: "npx", Args: []string{"server3"}},
				},
				MCP: config.MCPConfig{
					Allowed:  []string{"github", "notion", "slack"},
					Excluded: []string{"notion"},
				},
			},
			expectedCount: 2, // github and slack (notion excluded)
			shouldError:   false,
		},
		{
			name: "all servers filtered out",
			config: &config.Config{
				MCPServers: map[string]config.MCPServer{
					"github": {Command: "npx", Args: []string{"server1"}},
					"notion": {Command: "npx", Args: []string{"server2"}},
				},
				MCP: config.MCPConfig{
					Excluded: []string{"github", "notion"},
				},
			},
			expectedCount: 0,
			shouldError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variables
			if tt.envSetup != nil {
				for key, value := range tt.envSetup {
					os.Setenv(key, value)
				}
			}

			// Cleanup after test
			defer func() {
				if tt.envSetup != nil {
					for key := range tt.envSetup {
						os.Unsetenv(key)
					}
				}
			}()

			configs, err := LoadConfigs(tt.config)

			if tt.shouldError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.shouldError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if len(configs) != tt.expectedCount {
				t.Errorf("expected %d configs, got %d", tt.expectedCount, len(configs))
			}

			// Verify each config has required fields
			for _, cfg := range configs {
				if cfg.Name == "" {
					t.Error("config missing name")
				}
				if cfg.ClientOptions.Name == "" {
					t.Error("config missing ClientOptions.Name")
				}
				if cfg.ClientOptions.Stdio == nil {
					t.Error("config missing Stdio config")
				} else {
					if cfg.ClientOptions.Stdio.Command == "" {
						t.Error("config missing Stdio.Command")
					}
				}
			}
		})
	}
}
