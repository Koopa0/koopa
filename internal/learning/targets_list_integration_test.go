// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for Store.Targets — the GET /api/admin/learning/targets
// picker source. Exercises the TargetsForList query's new logic: archived
// exclusion, case-insensitive title substring (q), domain filter, and the
// row cap (limit).
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/learning"
)

func sortedTargetIDs(in ...uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID{}, in...)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func TestTargets_ListFilters(t *testing.T) {
	truncateLearningTables(t)
	ctx := t.Context()
	store := learning.NewStore(testPool)

	bs := seedTarget(t, "Binary Search")
	bh := seedTarget(t, "Binary Heap")
	ll := seedTarget(t, "Linked List")
	arch := seedTarget(t, "Archived Problem")
	if _, err := testPool.Exec(ctx,
		`UPDATE learning_targets SET archived_at = now() WHERE id = $1`, arch); err != nil {
		t.Fatalf("archiving target: %v", err)
	}

	idsOf := func(rows []learning.TargetListRow) []uuid.UUID {
		out := make([]uuid.UUID, len(rows))
		for i := range rows {
			out[i] = rows[i].ID
		}
		slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		return out
	}

	tests := []struct {
		name   string
		filter learning.TargetListFilter
		want   []uuid.UUID
	}{
		{name: "q matches title case-insensitively", filter: learning.TargetListFilter{Q: "binary", Limit: 50}, want: sortedTargetIDs(bs, bh)},
		{name: "no filter excludes archived", filter: learning.TargetListFilter{Limit: 50}, want: sortedTargetIDs(bs, bh, ll)},
		{name: "domain filter matches", filter: learning.TargetListFilter{Domain: "leetcode", Limit: 50}, want: sortedTargetIDs(bs, bh, ll)},
		{name: "unknown domain is empty", filter: learning.TargetListFilter{Domain: "nonexistent", Limit: 50}, want: []uuid.UUID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := store.Targets(ctx, tt.filter)
			if err != nil {
				t.Fatalf("Targets() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, idsOf(rows)); diff != "" {
				t.Errorf("Targets() ids mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTargets_LimitCaps(t *testing.T) {
	truncateLearningTables(t)
	ctx := t.Context()
	store := learning.NewStore(testPool)
	seedTarget(t, "Alpha")
	seedTarget(t, "Bravo")
	seedTarget(t, "Charlie")

	rows, err := store.Targets(ctx, learning.TargetListFilter{Limit: 2})
	if err != nil {
		t.Fatalf("Targets() error = %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("Targets(limit=2) returned %d rows, want 2", len(rows))
	}
	// ORDER BY title ASC → Alpha, Bravo.
	if rows[0].Title != "Alpha" || rows[1].Title != "Bravo" {
		t.Errorf("Targets(limit=2) titles = [%q, %q], want [Alpha, Bravo]", rows[0].Title, rows[1].Title)
	}
}
