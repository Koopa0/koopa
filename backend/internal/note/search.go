package note

import (
	"cmp"
	"slices"
)

// RRFMerge combines text search results and filter results using Reciprocal Rank
// Fusion with k=60. When a note appears in both result sets, its scores are summed,
// boosting items that rank well in both text and filter searches.
//
// Returns merged results sorted by combined score descending, capped at limit.
func RRFMerge(textResults []SearchResult, filterResults []Note, limit int) []MergedResult {
	const k = 60.0
	scores := make(map[int64]float64)
	notes := make(map[int64]Note)

	for rank := range textResults {
		r := textResults[rank]
		scores[r.ID] += 1.0 / (k + float64(rank))
		notes[r.ID] = r.Note
	}
	for rank := range filterResults {
		n := &filterResults[rank]
		scores[n.ID] += 1.0 / (k + float64(rank))
		if _, ok := notes[n.ID]; !ok {
			notes[n.ID] = *n
		}
	}

	// Collect and sort by score descending.
	entries := make([]MergedResult, 0, len(scores))
	for id, score := range scores {
		entries = append(entries, MergedResult{Note: notes[id], Score: score})
	}
	slices.SortFunc(entries, func(a, b MergedResult) int {
		return cmp.Compare(b.Score, a.Score) // descending
	})

	if limit <= 0 {
		return nil
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}
