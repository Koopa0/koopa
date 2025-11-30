package config

// DatadogConfig holds Datadog APM tracing configuration.
//
// Tracing uses the local Datadog Agent for OTLP ingestion.
// See internal/observability/datadog.go for detailed setup instructions.
type DatadogConfig struct {
	// APIKey is the Datadog API key (optional, for observability)
	APIKey string `mapstructure:"api_key" json:"api_key" sensitive:"true"`
	// AgentHost is the Datadog Agent OTLP endpoint (default: localhost:4318)
	AgentHost string `mapstructure:"agent_host"`
	// Environment is the deployment environment tag (default: dev)
	Environment string `mapstructure:"environment"`
	// ServiceName is the service name in Datadog APM (default: koopa)
	ServiceName string `mapstructure:"service_name"`
}
