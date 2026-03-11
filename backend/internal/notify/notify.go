// Package notify provides multi-channel text notification delivery.
package notify

import (
	"context"
	"errors"
	"log/slog"
)

// Notifier sends a text notification to an external channel.
type Notifier interface {
	Send(ctx context.Context, text string) error
}

// Compile-time interface checks.
var (
	_ Notifier = (*LINE)(nil)
	_ Notifier = (*Telegram)(nil)
	_ Notifier = (*Multi)(nil)
	_ Notifier = (*Noop)(nil)
)

// Multi fans out notifications to all wrapped notifiers.
type Multi struct {
	notifiers []Notifier
}

// NewMulti returns a Multi that sends to all given notifiers.
func NewMulti(notifiers ...Notifier) *Multi {
	return &Multi{notifiers: notifiers}
}

// Send calls Send on every notifier, joining any errors with errors.Join.
func (m *Multi) Send(ctx context.Context, text string) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Send(ctx, text); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Noop logs the notification text and returns nil.
// Used when no provider is configured.
type Noop struct {
	logger *slog.Logger
}

// NewNoop returns a Noop notifier that logs messages.
func NewNoop(logger *slog.Logger) *Noop {
	return &Noop{logger: logger}
}

// Send logs the text at info level and returns nil.
func (n *Noop) Send(_ context.Context, text string) error {
	n.logger.Info("noop notification", "text", text)
	return nil
}
