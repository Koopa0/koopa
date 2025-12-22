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

// retryableError determines if an error should trigger a retry.
func retryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Rate limit errors - always retry
	if containsAny(errStr, "rate limit", "quota exceeded", "429") {
		return true
	}

	// Transient server errors - retry
	if containsAny(errStr, "500", "502", "503", "504", "unavailable") {
		return true
	}

	// Network errors - retry
	if containsAny(errStr, "connection reset", "timeout", "temporary") {
		return true
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
func (c *Chat) executeWithRetry(
	ctx context.Context,
	opts []ai.PromptExecuteOption,
) (*ai.ModelResponse, error) {
	var lastErr error
	delay := c.retryConfig.InitialInterval
	start := time.Now() // Track elapsed time

	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		// Rate limit EACH attempt (per golang-master review)
		if c.rateLimiter != nil {
			if err := c.rateLimiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limit wait: %w", err)
			}
		}

		// Attempt execution
		resp, err := c.prompt.Execute(ctx, opts...)
		if err == nil {
			elapsed := time.Since(start)
			c.logger.Debug("prompt executed successfully",
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
		if attempt == c.retryConfig.MaxRetries {
			break
		}

		// Exponential backoff with context cancellation check
		c.logger.Debug("retrying after error",
			"attempt", attempt+1,
			"delay", delay,
			"elapsed", time.Since(start),
			"error", err,
		)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
		case <-time.After(delay):
			delay = min(delay*2, c.retryConfig.MaxInterval)
		}
	}

	elapsed := time.Since(start)
	return nil, fmt.Errorf("prompt execute after %d retries (elapsed: %v): %w",
		c.retryConfig.MaxRetries, elapsed, lastErr)
}
