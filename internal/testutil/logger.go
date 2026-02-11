package testutil

import (
	"log/slog"
)

// DiscardLogger returns a *slog.Logger that discards all output.
// Use this in tests to reduce log noise.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
