package config

import "testing"

// TestPlugins tests that Plugins() returns correct plugins
func TestPlugins(t *testing.T) {
	cfg := &Config{}
	plugins := cfg.Plugins()

	if len(plugins) == 0 {
		t.Error("expected at least one plugin")
	}

	// Should return GoogleAI plugin
	if len(plugins) != 1 {
		t.Errorf("expected exactly 1 plugin, got %d", len(plugins))
	}
}
