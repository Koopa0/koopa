package observability

import (
	"context"
	"testing"
)

func TestSetupDatadog_DefaultAgentHost(t *testing.T) {
	// NOTE: not parallel — SetupDatadog modifies global state (os.Setenv, TracerProvider)

	cfg := Config{
		AgentHost:   "", // Empty should use default
		Environment: "test",
		ServiceName: "test-service",
	}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	// Should not fail even with empty AgentHost
	if err != nil {
		t.Fatalf("SetupDatadog() unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("SetupDatadog() shutdown = nil, want non-nil")
	}

	// Cleanup
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown() unexpected error: %v", err)
	}
}

func TestSetupDatadog_CustomAgentHost(t *testing.T) {
	// NOTE: not parallel — SetupDatadog modifies global state (os.Setenv, TracerProvider)

	cfg := Config{
		AgentHost:   "custom-host:4318",
		Environment: "staging",
		ServiceName: "custom-service",
	}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	// Should not fail with custom host
	if err != nil {
		t.Fatalf("SetupDatadog() unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("SetupDatadog() shutdown = nil, want non-nil")
	}

	// Cleanup
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown() unexpected error: %v", err)
	}
}

func TestSetupDatadog_AgentUnavailable_GracefulDegradation(t *testing.T) {
	// NOTE: not parallel — SetupDatadog modifies global state (os.Setenv, TracerProvider)

	// Point to a non-existent agent
	cfg := Config{
		AgentHost:   "localhost:99999", // Invalid port
		Environment: "test",
		ServiceName: "graceful-test",
	}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	// Should NOT fail - graceful degradation
	// The exporter creation may succeed but spans will fail to export silently
	if err != nil {
		t.Fatalf("SetupDatadog() unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("SetupDatadog() shutdown = nil, want non-nil")
	}

	// Shutdown should not panic
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown() unexpected error: %v", err)
	}
}

func TestSetupDatadog_EmptyConfig(t *testing.T) {
	// NOTE: not parallel — SetupDatadog modifies global state (os.Setenv, TracerProvider)

	// All empty config - should use defaults
	cfg := Config{}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	if err != nil {
		t.Fatalf("SetupDatadog() unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("SetupDatadog() shutdown = nil, want non-nil")
	}

	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown() unexpected error: %v", err)
	}
}

func TestDefaultAgentHost_Value(t *testing.T) {
	t.Parallel()

	if got, want := DefaultAgentHost, "localhost:4318"; got != want {
		t.Errorf("DefaultAgentHost = %q, want %q", got, want)
	}
}
