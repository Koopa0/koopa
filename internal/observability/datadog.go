// Package observability provides OpenTelemetry integration for distributed tracing.
//
// # Architecture Decision: Datadog Agent Mode
//
// We use the Datadog Agent for OTLP ingestion instead of direct API endpoint.
// This decision was made because:
//
//   - Direct OTLP Traces API is in Preview status (as of Nov 2025)
//   - Agent provides better reliability with local buffering and retry
//   - Lower latency (localhost vs internet roundtrip)
//   - Agent handles authentication - no need to pass DD_API_KEY in app
//   - Supports all Datadog features (metrics, logs, traces in one agent)
//
// # Prerequisites
//
// 1. Datadog Account with US5 region (or your region)
// 2. DD_API_KEY from https://us5.datadoghq.com → Organization Settings → API Keys
//
// # macOS Installation
//
// Install Datadog Agent:
//
//	DD_API_KEY="your-key" DD_SITE="us5.datadoghq.com" \
//	  bash -c "$(curl -L https://install.datadoghq.com/scripts/install_mac_os.sh)"
//
// # Enable OTLP Receiver
//
// Add to /opt/datadog-agent/etc/datadog.yaml (at the end of file):
//
//	otlp_config:
//	  receiver:
//	    protocols:
//	      http:
//	        endpoint: "localhost:4318"
//	  traces:
//	    enabled: true
//	    span_name_as_resource_name: true
//
// # Restart Agent
//
// Option 1 - Using launchctl:
//
//	sudo launchctl stop com.datadoghq.agent
//	sudo launchctl start com.datadoghq.agent
//
// Option 2 - Kill and restart:
//
//	sudo pkill -9 -f datadog
//	sudo /opt/datadog-agent/bin/agent/agent run &
//
// # Option 3 - Use Datadog Agent GUI app
//
// # Verify OTLP is Enabled
//
//	datadog-agent status | grep -A 5 "OTLP"
//
// Expected output:
//
//	OTLP
//	====
//	  Status: Enabled
//	  Collector status: Running
//
// # View Traces in Datadog
//
// After running koopa with tracing enabled:
//   - Go to https://us5.datadoghq.com/apm/traces
//   - Search for service:koopa or your configured service name
//   - Traces appear within 1-2 minutes after app shutdown (flush)
//
// # Troubleshooting
//
// Agent not running:
//
//	launchctl list | grep datadog  # PID should not be "-"
//
// Check Agent logs:
//
//	sudo tail -50 /var/log/datadog/agent.log
//
// Test OTLP endpoint:
//
//	curl -v http://localhost:4318/v1/traces
//
// # Configuration
//
// Environment variables (optional):
//   - DD_AGENT_HOST: Override agent host (default: localhost:4318)
//   - DD_ENV: Environment tag (default: dev)
//   - DD_SERVICE: Service name (default: koopa)
//
// Config file (~/.koopa/config.yaml):
//
//	datadog:
//	  agent_host: "localhost:4318"
//	  environment: "dev"
//	  service_name: "koopa"
package observability

import (
	"context"
	"log/slog"
	"os"

	"github.com/firebase/genkit/go/core/tracing"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config for Datadog OTEL setup.
type Config struct {
	// AgentHost is the Datadog Agent OTLP endpoint (default: localhost:4318)
	AgentHost string
	// Environment is the deployment environment (dev, staging, prod)
	Environment string
	// ServiceName is the service name shown in Datadog APM
	ServiceName string
}

// DefaultAgentHost is the default Datadog Agent OTLP HTTP endpoint.
const DefaultAgentHost = "localhost:4318"

// SetupDatadog registers a Datadog Agent exporter with Genkit's TracerProvider.
// Traces are sent to the local Datadog Agent via OTLP HTTP protocol.
//
// Returns a shutdown function that flushes pending spans.
// If AgentHost is empty, uses DefaultAgentHost (localhost:4318).
func SetupDatadog(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	agentHost := cfg.AgentHost
	if agentHost == "" {
		agentHost = DefaultAgentHost
	}

	// Set OTEL_SERVICE_NAME for Genkit's TracerProvider to pick up
	// This ensures the service name appears correctly in Datadog APM
	if cfg.ServiceName != "" {
		_ = os.Setenv("OTEL_SERVICE_NAME", cfg.ServiceName)
	}
	if cfg.Environment != "" {
		_ = os.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment="+cfg.Environment)
	}

	// Create OTLP HTTP exporter pointing to local Datadog Agent
	// Agent handles authentication and forwarding to Datadog backend
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(agentHost),
		otlptracehttp.WithInsecure(), // localhost doesn't need TLS
	)
	if err != nil {
		slog.Warn("failed to create datadog exporter, tracing disabled", "error", err)
		return func(context.Context) error { return nil }, nil
	}

	// Register BatchSpanProcessor with Genkit's TracerProvider
	processor := sdktrace.NewBatchSpanProcessor(exporter)
	tracing.TracerProvider().RegisterSpanProcessor(processor)

	slog.Debug("datadog tracing enabled",
		"agent", agentHost,
		"service", cfg.ServiceName,
		"environment", cfg.Environment,
	)

	// Create a test span to verify the pipeline works
	tracer := tracing.TracerProvider().Tracer("koopa-init")
	_, span := tracer.Start(ctx, "koopa.init")
	span.End()
	slog.Debug("test span created for datadog verification")

	return tracing.TracerProvider().Shutdown, nil
}
