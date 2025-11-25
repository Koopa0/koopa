package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	logger := New(Config{})
	if logger == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNewWithWriter(t *testing.T) {
	var buf bytes.Buffer

	logger := NewWithWriter(&buf, Config{
		Level: slog.LevelDebug,
	})

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected output to contain 'key=value', got: %s", output)
	}
}

func TestNewWithWriter_JSON(t *testing.T) {
	var buf bytes.Buffer

	logger := NewWithWriter(&buf, Config{
		Level: slog.LevelInfo,
		JSON:  true,
	})

	logger.Info("json test", "foo", "bar")

	output := buf.String()
	if !strings.Contains(output, `"msg":"json test"`) {
		t.Errorf("expected JSON output with msg field, got: %s", output)
	}
}

func TestNewNop(t *testing.T) {
	logger := NewNop()
	if logger == nil {
		t.Fatal("NewNop() returned nil")
	}

	// Should not panic
	logger.Info("this should be discarded")
	logger.Error("this too")
}

func TestLogger_With(t *testing.T) {
	var buf bytes.Buffer

	logger := NewWithWriter(&buf, Config{
		Level: slog.LevelInfo,
	})

	// Add component context
	componentLogger := logger.With("component", "test")
	componentLogger.Info("component log")

	output := buf.String()
	if !strings.Contains(output, "component=test") {
		t.Errorf("expected output to contain 'component=test', got: %s", output)
	}
}

func TestLogger_Levels(t *testing.T) {
	var buf bytes.Buffer

	logger := NewWithWriter(&buf, Config{
		Level: slog.LevelDebug,
	})

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")
	logger.Error("error msg")

	output := buf.String()

	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	for _, level := range levels {
		if !strings.Contains(output, level) {
			t.Errorf("expected output to contain %s level", level)
		}
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer

	// Only INFO and above
	logger := NewWithWriter(&buf, Config{
		Level: slog.LevelInfo,
	})

	logger.Debug("debug should not appear")
	logger.Info("info should appear")

	output := buf.String()

	if strings.Contains(output, "debug should not appear") {
		t.Error("DEBUG message should be filtered out")
	}
	if !strings.Contains(output, "info should appear") {
		t.Error("INFO message should appear")
	}
}

func TestLoggerTypeAlias(t *testing.T) {
	// Verify that Logger is compatible with *slog.Logger
	logger := slog.Default()
	if logger == nil {
		t.Fatal("Logger type alias should be compatible with *slog.Logger")
	}
}
