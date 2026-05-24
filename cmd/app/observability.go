// observability.go bootstraps the OTel SDK with a Prometheus exporter so
// that the VPS Prometheus scrape job (job=blog-backend) can pull the
// process's metrics from GET /metrics.
//
// The setup is gated by KOOPA_OBSERVABILITY_ENABLED (default true). When
// disabled, setupObservability returns a noop.MeterProvider and a 404
// metrics handler so callers wire identically and can be flipped off
// without a deploy.
//
// Subsequent tasks layer on top of this bootstrap:
//   - Task 2 adds custom histogram buckets + name renames via Views.
//   - Task 3 emits the HTTP request histogram + counter from middleware.
//   - Task 6 wires otelpgx using the global MeterProvider set here.
//   - Task 7 instruments background goroutines (feed scheduler, FSRS, agent sync).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

// observabilityConfig is the subset of app config consumed by setupObservability.
type observabilityConfig struct {
	Enabled        bool
	ServiceName    string
	ServiceVersion string
	Environment    string
}

// setupObservability bootstraps the OTel MeterProvider and a Prometheus
// scrape handler. The returned shutdown func flushes pending exports and
// must be called before process exit.
//
// When cfg.Enabled is false, the returned MeterProvider is a zero-cost
// noop and the returned handler responds 404. This lets the rest of
// main.go wire the values unconditionally — flipping
// KOOPA_OBSERVABILITY_ENABLED=false requires only a process restart, no
// code path changes.
func setupObservability(
	ctx context.Context,
	cfg observabilityConfig,
	logger *slog.Logger,
) (metric.MeterProvider, http.Handler, func(context.Context) error, error) {
	if !cfg.Enabled {
		logger.Info("observability disabled")
		provider := noop.NewMeterProvider()
		otel.SetMeterProvider(provider)
		return provider, http.NotFoundHandler(), func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironmentName(cfg.Environment),
		),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating otel resource: %w", err)
	}

	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}

	// View: rename http.server.request.duration → http.request.duration
	// (Prom exporter then emits http_request_duration_seconds_*) AND apply
	// custom histogram boundaries dense in the 100-500ms range to give
	// usable p95/p99 interpolation at koopa's observed 200ms median.
	// Default OTel boundaries have only 3 edges between 100ms and 500ms,
	// which would leave p99 with ±150ms interpolation error.
	httpDurationView := sdkmetric.NewView(
		sdkmetric.Instrument{Name: "http.server.request.duration"},
		sdkmetric.Stream{
			Name: "http.request.duration",
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0, 2.0, 5.0},
			},
		},
	)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(exporter),
		sdkmetric.WithView(httpDurationView),
	)
	otel.SetMeterProvider(provider)

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})

	logger.Info("observability initialized",
		"service", cfg.ServiceName,
		"version", cfg.ServiceVersion,
		"environment", cfg.Environment,
	)

	return provider, handler, provider.Shutdown, nil
}
