package session

import "errors"

// Message status constants for streaming lifecycle.
const (
	// StatusStreaming indicates the message is being streamed (AI generating).
	StatusStreaming = "streaming"

	// StatusCompleted indicates the message has been fully generated.
	StatusCompleted = "completed"

	// StatusFailed indicates the message generation failed.
	StatusFailed = "failed"
)

// History limit constants.
const (
	// DefaultHistoryLimit is the default number of messages to load.
	DefaultHistoryLimit int32 = 100

	// MaxHistoryLimit is the absolute maximum to prevent OOM.
	MaxHistoryLimit int32 = 10000

	// MinHistoryLimit is the minimum allowed value for history limit.
	MinHistoryLimit int32 = 10
)

// Sentinel errors for session operations.
// These errors are part of the Store's public API and should be checked using errors.Is().
//
// Example:
//
//	sess, err := store.Session(ctx, id)
//	if errors.Is(err, session.ErrSessionNotFound) {
//	    // Handle missing session
//	}
//
// ErrSessionNotFound indicates the requested session does not exist in the database.
var ErrSessionNotFound = errors.New("session not found")

// NormalizeHistoryLimit normalizes the history limit value.
// Returns DefaultHistoryLimit for zero/negative values.
// Clamps to MinHistoryLimit/MaxHistoryLimit as bounds.
func NormalizeHistoryLimit(limit int32) int32 {
	if limit <= 0 {
		return DefaultHistoryLimit
	}
	if limit < MinHistoryLimit {
		return MinHistoryLimit
	}
	if limit > MaxHistoryLimit {
		return MaxHistoryLimit
	}
	return limit
}
