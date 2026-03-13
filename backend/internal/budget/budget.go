// Package budget tracks daily LLM token usage with an in-memory atomic counter.
package budget

import (
	"errors"
	"sync/atomic"
)

// ErrOverBudget indicates the daily token budget has been exceeded.
var ErrOverBudget = errors.New("daily token budget exceeded")

// Budget tracks daily LLM token usage.
type Budget struct {
	used  atomic.Int64
	limit int64
}

// New returns a Budget with the given daily limit.
func New(dailyLimit int64) *Budget {
	return &Budget{limit: dailyLimit}
}

// Reserve atomically checks and adds tokens in a single operation.
// Returns ErrOverBudget if the reservation would exceed the daily limit.
func (b *Budget) Reserve(tokens int64) error {
	for {
		current := b.used.Load()
		if current+tokens > b.limit {
			return ErrOverBudget
		}
		if b.used.CompareAndSwap(current, current+tokens) {
			return nil
		}
	}
}

// Reset resets the counter to zero. Called by midnight cron.
func (b *Budget) Reset() {
	b.used.Store(0)
}

// Used returns current usage.
func (b *Budget) Used() int64 {
	return b.used.Load()
}
