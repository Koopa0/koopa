package exec

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/koopa0/blog-backend/internal/notify"
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

// NotifyAlerter sends flow failure alerts via a notification provider.
type NotifyAlerter struct {
	notifier notify.Notifier
	logger   *slog.Logger
}

// NewNotifyAlerter returns an Alerter that sends failure notifications
// via the given notifier.
func NewNotifyAlerter(n notify.Notifier, logger *slog.Logger) *NotifyAlerter {
	return &NotifyAlerter{notifier: n, logger: logger}
}

// Alert sends a notification for a permanently failed flow run.
func (a *NotifyAlerter) Alert(ctx context.Context, run *Run) error {
	errMsg := ""
	if run.Error != nil {
		errMsg = *run.Error
	}
	text := fmt.Sprintf("[ALERT] Flow run failed\nFlow: %s\nRun ID: %s\nAttempt: %d\nError: %s",
		run.FlowName, run.ID, run.Attempt, errMsg)

	if err := a.notifier.Send(ctx, text); err != nil {
		a.logger.Error("sending flow alert notification", "run_id", run.ID, "error", err)
		return err
	}
	return nil
}
