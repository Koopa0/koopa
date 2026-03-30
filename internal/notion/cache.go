package notion

import (
	"fmt"

	"github.com/dgraph-io/ristretto/v2"
)

// NewSourceCache returns a ristretto cache for Notion database_id → role mappings.
// The cache is shared between Handler and SourceHandler, so it is created once
// by the wiring layer and passed to both.
func NewSourceCache() (*ristretto.Cache[string, string], error) {
	c, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 50, // 10x expected items (~4 sources)
		MaxCost:     10, // count-based: max 10 items
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating notion source cache: %w", err)
	}
	return c, nil
}
