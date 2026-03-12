package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// httpRequestsTotal counts each HTTP request, labeled by method/path/status.
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "path", "status"},
	)

	// httpRequestDuration records request latency distribution.
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	// httpRequestsInFlight tracks currently-processing requests.
	httpRequestsInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "http_requests_in_flight",
		Help: "Number of HTTP requests currently being processed.",
	})
)

// RegisterMetrics registers HTTP metrics with the given registerer.
// Called once from the server constructor; avoids init() side effects.
func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(httpRequestsTotal, httpRequestDuration, httpRequestsInFlight)
}

// MetricsHandler returns the Prometheus metrics HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// prometheusMiddleware records HTTP metrics for each request.
// Must be the outermost middleware to measure full request duration.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(sw.status)
		path := normalizePath(r.URL.Path)

		httpRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path, status).Observe(duration)
	})
}

// pathPattern maps a URL prefix to the segment index containing a dynamic ID.
// Longer prefixes must appear first to avoid shorter prefix matches.
var pathPatterns = []struct {
	prefix string
	idIdx  int
}{
	{"/api/admin/flow/polish/", 5},
	{"/api/admin/contents/", 4},
	{"/api/admin/review/", 4},
	{"/api/admin/collected/", 4},
	{"/api/admin/projects/", 4},
	{"/api/admin/topics/", 4},
	{"/api/admin/tracking/", 4},
	{"/api/admin/flow-runs/", 4},
	{"/api/admin/feeds/", 4},
	{"/api/contents/related/", 4},
	{"/api/contents/by-type/", 4},
	{"/api/contents/", 3},
	{"/api/topics/", 3},
	{"/api/projects/", 3},
}

// normalizePath replaces dynamic path segments with :id to prevent
// high-cardinality label explosion in Prometheus.
func normalizePath(path string) string {
	for _, p := range pathPatterns {
		if strings.HasPrefix(path, p.prefix) {
			parts := strings.Split(path, "/")
			if len(parts) > p.idIdx {
				parts[p.idIdx] = ":id"
				return strings.Join(parts, "/")
			}
		}
	}
	return path
}
