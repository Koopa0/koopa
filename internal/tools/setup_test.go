package tools

import (
	"github.com/koopa0/koopa/internal/log"
)

// testLogger returns a no-op logger for testing.
func testLogger() log.Logger {
	return log.NewNop()
}
