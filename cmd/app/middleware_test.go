// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// testMeter spins up a MeterProvider backed by a ManualReader so tests
// can inspect emitted metric data points.
func testMeter(t *testing.T) (func(http.Handler) http.Handler, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	mw, err := httpMetrics(provider.Meter("test"))
	if err != nil {
		t.Fatalf("httpMetrics: %v", err)
	}
	return mw, reader
}

// findMetric returns the metric with the given name from the most
// recently collected ResourceMetrics.
func findMetric(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	t.Fatalf("metric %q not found in collected data", name)
	return metricdata.Metrics{}
}

func TestHttpMetrics_StatusLabel(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"ok", 200, "200"},
		{"moved", 301, "301"},
		{"not_found", 404, "404"},
		{"server_error", 500, "500"},
		{"teapot", 418, "418"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw, reader := testMeter(t)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
			}))

			req := httptest.NewRequest("GET", "/test", http.NoBody)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(t.Context(), &rm); err != nil {
				t.Fatalf("collect: %v", err)
			}

			counter := findMetric(t, rm, "http.requests")
			sum := counter.Data.(metricdata.Sum[int64])
			if len(sum.DataPoints) != 1 {
				t.Fatalf("want 1 counter data point, got %d", len(sum.DataPoints))
			}
			status, _ := sum.DataPoints[0].Attributes.Value(attribute.Key("status"))
			if got := status.AsString(); got != tc.expect {
				t.Errorf("status label = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestHttpMetrics_RouteLabel(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string // "" means no mux pattern registered
		reqMethod string
		reqPath   string
		expect    string
	}{
		{
			name:      "matched_pattern",
			pattern:   "GET /api/items/{id}",
			reqMethod: "GET",
			reqPath:   "/api/items/abc",
			expect:    "GET /api/items/{id}",
		},
		{
			name:      "unmatched_falls_back_to_unknown",
			pattern:   "",
			reqMethod: "GET",
			reqPath:   "/unregistered/path",
			expect:    "unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw, reader := testMeter(t)
			mux := http.NewServeMux()
			if tc.pattern != "" {
				mux.HandleFunc(tc.pattern, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			}
			handler := mw(mux)

			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, http.NoBody)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(t.Context(), &rm); err != nil {
				t.Fatalf("collect: %v", err)
			}

			counter := findMetric(t, rm, "http.requests")
			sum := counter.Data.(metricdata.Sum[int64])
			if len(sum.DataPoints) != 1 {
				t.Fatalf("want 1 data point, got %d", len(sum.DataPoints))
			}
			route, _ := sum.DataPoints[0].Attributes.Value(attribute.Key("route"))
			if got := route.AsString(); got != tc.expect {
				t.Errorf("route label = %q, want %q", got, tc.expect)
			}
		})
	}
}

// TestHttpMetrics_RecordsDespitePanic confirms the defer-based observation
// fires even when the inner handler panics, AND stamps status="500" so
// alerts on status=~"5.." see panicked requests as errors. Without the
// status stamp, sr.code would still be the default 200 (the panicking
// handler never reached WriteHeader) and the metric would silently
// classify panics as successful — the opposite of the design goal.
func TestHttpMetrics_RecordsDespitePanic(t *testing.T) {
	mw, reader := testMeter(t)
	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("intentional test panic")
	})
	// recovery wraps OUTSIDE httpMetrics so panic is caught after our defer.
	// Discard logs from recovery — we expect the panic and don't want noise.
	silent := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := recovery(silent)(mw(panicHandler))

	req := httptest.NewRequest("GET", "/boom", http.NoBody)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	counter := findMetric(t, rm, "http.requests")
	sum := counter.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 {
		t.Fatalf("want 1 counter data point after panic, got %d", len(sum.DataPoints))
	}
	if sum.DataPoints[0].Value != 1 {
		t.Errorf("counter value = %d, want 1", sum.DataPoints[0].Value)
	}
	status, _ := sum.DataPoints[0].Attributes.Value(attribute.Key("status"))
	if got := status.AsString(); got != "500" {
		t.Errorf("status on panic = %q, want %q (alerts on 5xx would miss panics)", got, "500")
	}

	hist := findMetric(t, rm, "http.server.request.duration")
	hd := hist.Data.(metricdata.Histogram[float64])
	if len(hd.DataPoints) != 1 {
		t.Fatalf("want 1 histogram data point after panic, got %d", len(hd.DataPoints))
	}
	if hd.DataPoints[0].Count != 1 {
		t.Errorf("histogram count = %d, want 1", hd.DataPoints[0].Count)
	}
	histStatus, _ := hd.DataPoints[0].Attributes.Value(attribute.Key("status"))
	if got := histStatus.AsString(); got != "500" {
		t.Errorf("histogram status on panic = %q, want %q", got, "500")
	}
}

// TestHttpMetrics_SkipsInfraRoutes confirms /metrics, /healthz, /readyz
// produce no data point so high-volume scrape and uptime traffic doesn't
// drown out user-facing request observations.
func TestHttpMetrics_SkipsInfraRoutes(t *testing.T) {
	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			mw, reader := testMeter(t)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest("GET", path, http.NoBody)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(t.Context(), &rm); err != nil {
				t.Fatalf("collect: %v", err)
			}
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					if m.Name == "http.requests" {
						sum := m.Data.(metricdata.Sum[int64])
						if len(sum.DataPoints) > 0 {
							t.Errorf("scrape on %s produced %d data points, want 0", path, len(sum.DataPoints))
						}
					}
				}
			}
		})
	}
}

// TestHttpMetrics_CounterAndHistogramAgree guards against future drift —
// if someone removes the counter or the histogram observation, the two
// instruments will report different totals. Existing Grafana alerts
// query both (rate(http_requests_total) and histogram_quantile on
// http_request_duration_seconds), and divergence would produce
// misleading dashboards.
func TestHttpMetrics_CounterAndHistogramAgree(t *testing.T) {
	mw, reader := testMeter(t)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const N = 7
	for i := range N {
		req := httptest.NewRequest("GET", fmt.Sprintf("/req/%d", i), http.NoBody)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	counter := findMetric(t, rm, "http.requests")
	sum := counter.Data.(metricdata.Sum[int64])
	var counterTotal int64
	for _, dp := range sum.DataPoints {
		counterTotal += dp.Value
	}

	hist := findMetric(t, rm, "http.server.request.duration")
	hd := hist.Data.(metricdata.Histogram[float64])
	var histTotal uint64
	for _, dp := range hd.DataPoints {
		histTotal += dp.Count
	}

	if uint64(counterTotal) != histTotal || counterTotal != N {
		t.Errorf("counter=%d histogram=%d want=%d (all equal)", counterTotal, histTotal, N)
	}
}
