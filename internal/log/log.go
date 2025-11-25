// Package log provides a unified logging infrastructure for the koopa application.
//
// This package provides:
//   - A type alias for *slog.Logger to use as DI dependency
//   - Factory functions to create configured loggers
//   - A Nop logger for testing
//
// Design Philosophy:
//   - Use Dependency Injection (DI) for loggers, not globals
//   - Each component receives a logger via constructor
//   - Components can add context via logger.With()
//
// Usage:
//
//	// Create a logger at application startup
//	logger := log.New(log.Config{Level: slog.LevelDebug})
//
//	// Inject into components with context
//	fileToolset := tools.NewFileToolset(pathVal, logger.With("component", "file"))
//	agent := agent.New(logger.With("component", "agent"), ...)
//
//	// In tests, use Nop logger or capture to buffer
//	testLogger := log.NewNop()
//	// or
//	var buf bytes.Buffer
//	testLogger := log.NewWithWriter(&buf, log.Config{})
package log

import (
	"io"
	"log/slog"
	"os"
)

// Logger is a type alias for *slog.Logger.
// Using the standard library type directly provides:
//   - Full compatibility with slog ecosystem
//   - Access to With() for adding context
//   - No need for custom interface definitions
//
// Components should accept log.Logger as a dependency.
type Logger = *slog.Logger

// Config defines logger configuration options.
type Config struct {
	// Level sets the minimum log level. Default: slog.LevelInfo
	Level slog.Level

	// JSON enables JSON format output. Default: false (text format)
	JSON bool

	// AddSource adds source file information to log entries. Default: false
	AddSource bool
}

// New creates a new logger with the given configuration.
// Output is written to os.Stderr by default.
//
// Example:
//
//	logger := log.New(log.Config{
//	    Level: slog.LevelDebug,
//	    JSON:  true,
//	})
func New(cfg Config) Logger {
	return NewWithWriter(os.Stderr, cfg)
}

// NewWithWriter creates a new logger that writes to the specified writer.
// Useful for testing or custom output destinations.
//
// Example:
//
//	var buf bytes.Buffer
//	logger := log.NewWithWriter(&buf, log.Config{})
//	// ... use logger
//	fmt.Println(buf.String()) // inspect log output
func NewWithWriter(w io.Writer, cfg Config) Logger {
	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if cfg.JSON {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}

// NewNop creates a logger that discards all output.
//
// WARNING: This should ONLY be used in tests. Never use NewNop() in production
// code as it will silently discard all logs, making debugging impossible.
// Production code should always use New() or NewWithWriter() with proper configuration.
//
// Example:
//
//	func TestSomething(t *testing.T) {
//	    logger := log.NewNop()
//	    sut := NewMyComponent(logger)
//	    // ... test without log noise
//	}
func NewNop() Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
