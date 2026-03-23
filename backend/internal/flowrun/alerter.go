package flowrun

import (
	"context"
	"log/slog"
)

// Alerter sends alerts when flow runs fail permanently.
type Alerter interface {
	Alert(ctx context.Context, run *Run) error
}

// LogAlerter logs permanently failed flow runs using slog.
type LogAlerter struct {
	logger *slog.Logger
}

// NewLogAlerter returns a LogAlerter.
func NewLogAlerter(logger *slog.Logger) *LogAlerter {
	return &LogAlerter{logger: logger}
}

// Alert logs a permanently failed flow run.
func (a *LogAlerter) Alert(_ context.Context, run *Run) error {
	a.logger.Error("flow run permanently failed",
		"run_id", run.ID,
		"flow_name", run.FlowName,
		"attempt", run.Attempt,
		"error", run.Error,
	)
	return nil
}
