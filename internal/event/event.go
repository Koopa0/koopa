// Package event provides a synchronous, in-process event bus.
// Synchronous by design: no goroutines, no channels, no lost events.
package event

import (
	"context"
	"errors"
	"sync"
)

// HandlerFunc processes an event payload.
type HandlerFunc func(ctx context.Context, payload any) error

// Bus is a synchronous event dispatcher.
// Handlers are called in registration order. If a handler returns an error,
// subsequent handlers for the same event still run (errors are collected).
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]HandlerFunc
}

// New returns a ready-to-use Bus.
func New() *Bus {
	return &Bus{handlers: make(map[string][]HandlerFunc)}
}

// On registers a handler for the given event name.
func (b *Bus) On(event string, fn HandlerFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[event] = append(b.handlers[event], fn)
}

// Emit dispatches the event to all registered handlers synchronously.
// All handlers run even if some return errors. Returns a joined error
// containing all handler errors, or nil if all succeeded.
func (b *Bus) Emit(ctx context.Context, event string, payload any) error {
	b.mu.RLock()
	fns := b.handlers[event]
	b.mu.RUnlock()

	var errs []error
	for _, fn := range fns {
		if err := fn(ctx, payload); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Event names for the Notion sync pipeline.
const (
	// NotionPageCreated fires when a new Notion page is detected during sync.
	NotionPageCreated = "notion.page.created"

	// NotionPageUpdated fires when an existing Notion page is modified.
	NotionPageUpdated = "notion.page.updated"
)

// Event names for the content sync pipeline.
const (
	// ObsidianNoteSynced fires when an Obsidian note is synced from GitHub.
	ObsidianNoteSynced = "obsidian.note.synced"

	// ObsidianNoteDeleted fires when an Obsidian note is removed from GitHub.
	ObsidianNoteDeleted = "obsidian.note.deleted"

	// ContentPublished fires when content transitions to published status.
	ContentPublished = "content.published"

	// ContentUpdated fires when existing content is modified.
	ContentUpdated = "content.updated"

	// WebhookGitHubPush fires when a GitHub push webhook is received.
	WebhookGitHubPush = "webhook.github.push"
)
