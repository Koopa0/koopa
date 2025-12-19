package mcp

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain enables goroutine leak detection for all tests in the mcp package.
// This catches resource cleanup issues in benchmarks and tests.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// HTTP/2 connection pool goroutines persist across tests
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net/http.(*http2clientConnReadLoop).run"),
		// OpenCensus stats worker is a global singleton that can't be stopped
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)
}
