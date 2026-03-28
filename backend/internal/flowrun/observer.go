package flowrun

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsObserver adapts a Prometheus HistogramVec to FlowObserver.
// Created in cmd/app/main.go and wired via Runner.SetObserver.
type MetricsObserver struct {
	duration *prometheus.HistogramVec
}

// NewMetricsObserver returns a MetricsObserver that records flow execution
// durations into the given histogram.
func NewMetricsObserver(duration *prometheus.HistogramVec) *MetricsObserver {
	return &MetricsObserver{duration: duration}
}

// ObserveFlowDuration records a flow execution duration by flow name and status.
func (o *MetricsObserver) ObserveFlowDuration(flowName, status string, d time.Duration) {
	o.duration.WithLabelValues(flowName, status).Observe(d.Seconds())
}
