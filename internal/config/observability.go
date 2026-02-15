package config

import (
	"encoding/json"
	"fmt"
)

// DatadogConfig holds Datadog APM tracing configuration.
//
// Tracing uses the local Datadog Agent for OTLP ingestion.
// Setup is inlined in internal/app/setup.go (provideOtelShutdown).
type DatadogConfig struct {
	// APIKey is the Datadog API key (optional, for observability)
	APIKey string `mapstructure:"api_key" json:"api_key"` // #nosec G117 -- masked in MarshalJSON, never serialized in plain text
	// AgentHost is the Datadog Agent OTLP endpoint (default: localhost:4318)
	AgentHost string `mapstructure:"agent_host" json:"agent_host"`
	// Environment is the deployment environment tag (default: dev)
	Environment string `mapstructure:"environment" json:"environment"`
	// ServiceName is the service name in Datadog APM (default: koopa)
	ServiceName string `mapstructure:"service_name" json:"service_name"`
}

// MarshalJSON implements json.Marshaler with sensitive field masking.
func (d DatadogConfig) MarshalJSON() ([]byte, error) {
	type alias DatadogConfig
	a := alias(d)
	a.APIKey = maskSecret(a.APIKey)
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal datadog config: %w", err)
	}
	return data, nil
}
