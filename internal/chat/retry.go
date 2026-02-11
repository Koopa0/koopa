package chat

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
)

// RetryConfig configures the retry behavior for LLM calls.
type RetryConfig struct {
	MaxRetries      int           // Maximum number of retry attempts
	InitialInterval time.Duration // Initial backoff interval
	MaxInterval     time.Duration // Maximum backoff interval
}

// DefaultRetryConfig returns sensible defaults for LLM API calls.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
	}
}

// retryablePatterns groups error substrings by category.
// Matched case-insensitively against err.Error().
//
// NOTE: This uses string matching because Genkit and LLM provider SDKs
// do not expose typed/sentinel errors for transient failures.
// This is a documented exception to the project rule against
// strings.Contains(err.Error(), ...).
// Re-evaluate if Genkit adds structured error types in a future version.
var retryablePatterns = [][]string{
	{"rate limit", "quota exceeded", "429"},      // rate limiting
	{"500", "502", "503", "504", "unavailable"},  // transient server errors
	{"connection reset", "timeout", "temporary"}, // network errors
}

// retryableError reports whether err is transient and should trigger a retry.
func retryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	for _, group := range retryablePatterns {
		if containsAny(errStr, group...) {
			return true
		}
	}
	return false
}

// containsAny checks if s contains any of the substrings (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// executeWithRetry executes prompt with exponential backoff retry.
// Uses stdlib only - no external dependencies.
//
// Features:
//   - Rate limits EACH attempt (per golang-master review)
//   - Tracks elapsed time for observability (per Rob Pike review)
//   - Exponential backoff with configurable max interval
func (a *Agent) executeWithRetry(
	ctx context.Context,
	opts []ai.PromptExecuteOption,
) (*ai.ModelResponse, error) {
	var lastErr error
	delay := a.retryConfig.InitialInterval
	start := time.Now() // Track elapsed time

	for attempt := 0; attempt <= a.retryConfig.MaxRetries; attempt++ {
		// Rate limit EACH attempt (per golang-master review)
		if a.rateLimiter != nil {
			if err := a.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limit wait: %w", err)
			}
		}

		// Attempt execution
		resp, err := a.prompt.Execute(ctx, opts...)
		if err == nil {
			elapsed := time.Since(start)
			a.logger.Debug("prompt executed successfully",
				"attempts", attempt+1,
				"elapsed", elapsed,
			)
			return resp, nil
		}

		lastErr = err

		// Non-retryable error - fail immediately
		if !retryableError(err) {
			return nil, fmt.Errorf("prompt execute: %w", err)
		}

		// Last attempt - don't sleep
		if attempt == a.retryConfig.MaxRetries {
			break
		}

		// Exponential backoff with context cancellation check
		a.logger.Debug("retrying after error",
			"attempt", attempt+1,
			"delay", delay,
			"elapsed", time.Since(start),
			"error", err,
		)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
		case <-time.After(delay):
			delay = min(delay*2, a.retryConfig.MaxInterval)
		}
	}

	elapsed := time.Since(start)
	return nil, fmt.Errorf("prompt execute after %d retries (elapsed: %v): %w",
		a.retryConfig.MaxRetries, elapsed, lastErr)
}
