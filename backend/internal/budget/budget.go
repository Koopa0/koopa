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

// Check returns nil if spending tokens would stay within budget, or ErrOverBudget.
func (b *Budget) Check(tokens int64) error {
	if b.used.Load()+tokens > b.limit {
		return ErrOverBudget
	}
	return nil
}

// Add records token usage.
func (b *Budget) Add(tokens int64) {
	b.used.Add(tokens)
}

// Reset resets the counter to zero. Called by midnight cron.
func (b *Budget) Reset() {
	b.used.Store(0)
}

// Used returns current usage.
func (b *Budget) Used() int64 {
	return b.used.Load()
}
