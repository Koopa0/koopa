package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupDatadog_DefaultAgentHost(t *testing.T) {
	t.Parallel()

	cfg := Config{
		AgentHost:   "", // Empty should use default
		Environment: "test",
		ServiceName: "test-service",
	}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	// Should not fail even with empty AgentHost
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Cleanup
	err = shutdown(ctx)
	assert.NoError(t, err)
}

func TestSetupDatadog_CustomAgentHost(t *testing.T) {
	t.Parallel()

	cfg := Config{
		AgentHost:   "custom-host:4318",
		Environment: "staging",
		ServiceName: "custom-service",
	}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	// Should not fail with custom host
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Cleanup
	err = shutdown(ctx)
	assert.NoError(t, err)
}

func TestSetupDatadog_AgentUnavailable_GracefulDegradation(t *testing.T) {
	t.Parallel()

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
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Shutdown should not panic
	err = shutdown(ctx)
	assert.NoError(t, err)
}

func TestSetupDatadog_EmptyConfig(t *testing.T) {
	t.Parallel()

	// All empty config - should use defaults
	cfg := Config{}

	ctx := context.Background()
	shutdown, err := SetupDatadog(ctx, cfg)

	require.NoError(t, err)
	require.NotNil(t, shutdown)

	err = shutdown(ctx)
	assert.NoError(t, err)
}

func TestDefaultAgentHost_Value(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "localhost:4318", DefaultAgentHost)
}
