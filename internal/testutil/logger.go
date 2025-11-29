package testutil

import (
	"log/slog"
)

// DiscardLogger returns a slog.Logger that discards all output.
// This is the standard library pattern for test loggers.
//
// Use this in tests to reduce noise. For components that use log.Logger
// (which is a type alias for *slog.Logger), use log.NewNop() directly.
//
// Note: log.Logger is a type alias for *slog.Logger, so this function
// and log.NewNop() return the same type. Prefer log.NewNop() when working
// with the internal/log package.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
