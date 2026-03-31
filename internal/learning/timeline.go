package learning

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// TimelineDay groups learning entries by date.
type TimelineDay struct {
	Date    string          `json:"date"`
	Entries []TimelineEntry `json:"entries"`
}

// TimelineEntry is a single learning record within a day.
type TimelineEntry struct {
	Slug                  string                  `json:"slug"`
	Title                 string                  `json:"title"`
	ContentType           string                  `json:"content_type"`
	Result                string                  `json:"result,omitempty"`
	Tags                  []string                `json:"tags"`
	LearningType          string                  `json:"learning_type,omitempty"`
	WeaknessObservations  []WeaknessObservation   `json:"weakness_observations,omitempty"`
	KeyConcepts           []KeyConcept            `json:"key_concepts,omitempty"`
	ConceptBreakdown      []ConceptBreakdownEntry `json:"concept_breakdown,omitempty"`
	SolveContext          *SolveContext           `json:"solve_context,omitempty"`
	VariationLinks        []VariationLink         `json:"variation_links,omitempty"`
	AlternativeApproaches []AlternativeApproach   `json:"alternative_approaches,omitempty"`
}

// KeyConcept is a structured concept from book-reading, course, or system-design metadata.
type KeyConcept struct {
	Name            string `json:"name"`
	Understanding   string `json:"understanding"`
	Connection      string `json:"connection,omitempty"`
	RetrievalTarget bool   `json:"retrieval_target,omitempty"`
}

// TimelineSummary holds aggregate stats for the timeline period.
type TimelineSummary struct {
	TotalEntries  int            `json:"total_entries"`
	ActiveDays    int            `json:"active_days"`
	CurrentStreak int            `json:"current_streak"`
	ByProject     map[string]int `json:"by_project"`
}

// TimelineResult is the full timeline response.
type TimelineResult struct {
	Days    []TimelineDay   `json:"days"`
	Summary TimelineSummary `json:"summary"`
}

// Timeline groups RichTagEntry records by day and computes summary stats.
// now is the reference time for streak calculation (typically time.Now()).
func Timeline(entries []content.RichTagEntry, now time.Time) TimelineResult {
	// Group entries by date string.
	dayMap := make(map[string][]TimelineEntry)
	projectCounts := make(map[string]int)

	for i := range entries {
		dateStr := entries[i].CreatedAt.Format(time.DateOnly)
		te := buildTimelineEntry(&entries[i])
		dayMap[dateStr] = append(dayMap[dateStr], te)

		if entries[i].ProjectSlug != "" {
			projectCounts[entries[i].ProjectSlug]++
		}
	}

	// Build sorted day list (most recent first).
	days := make([]TimelineDay, 0, len(dayMap))
	for date, entries := range dayMap {
		days = append(days, TimelineDay{Date: date, Entries: entries})
	}
	slices.SortFunc(days, func(a, b TimelineDay) int {
		if a.Date > b.Date {
			return -1
		}
		if a.Date < b.Date {
			return 1
		}
		return 0
	})

	return TimelineResult{
		Days: days,
		Summary: TimelineSummary{
			TotalEntries:  len(entries),
			ActiveDays:    len(dayMap),
			CurrentStreak: computeStreak(dayMap, now),
			ByProject:     projectCounts,
		},
	}
}

// computeStreak counts consecutive days with entries backwards from now.
// If today has entries, starts from today. Otherwise starts from yesterday.
func computeStreak(dayMap map[string][]TimelineEntry, now time.Time) int {
	today := now.Format(time.DateOnly)

	// Determine start date: today if it has entries, otherwise yesterday.
	start := now
	if _, ok := dayMap[today]; !ok {
		start = now.AddDate(0, 0, -1)
	}

	streak := 0
	for {
		dateStr := start.AddDate(0, 0, -streak).Format(time.DateOnly)
		if _, ok := dayMap[dateStr]; !ok {
			break
		}
		streak++
	}
	return streak
}

// buildTimelineEntry converts a RichTagEntry to a TimelineEntry,
// extracting structured metadata fields when present.
func buildTimelineEntry(e *content.RichTagEntry) TimelineEntry {
	te := TimelineEntry{
		Slug:        e.Slug,
		Title:       e.Title,
		ContentType: "til",
		Result:      extractResultTag(e.Tags),
		Tags:        e.Tags,
	}
	enrichTimelineMetadata(&te, e.AIMetadata)
	return te
}

// enrichTimelineMetadata extracts structured fields from ai_metadata into the entry.
func enrichTimelineMetadata(te *TimelineEntry, metadata json.RawMessage) {
	if len(metadata) == 0 {
		return
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return
	}

	unmarshalField(m, "learning_type", &te.LearningType)
	unmarshalField(m, "weakness_observations", &te.WeaknessObservations)
	unmarshalField(m, "key_concepts", &te.KeyConcepts)
	unmarshalField(m, "concept_breakdown", &te.ConceptBreakdown)
	unmarshalField(m, "variation_links", &te.VariationLinks)
	unmarshalField(m, "alternative_approaches", &te.AlternativeApproaches)

	if raw, ok := m["solve_context"]; ok {
		var sc SolveContext
		if err := json.Unmarshal(raw, &sc); err == nil {
			te.SolveContext = &sc
		}
	}
}

// unmarshalField extracts a JSON field into dst if it exists.
func unmarshalField[T any](m map[string]json.RawMessage, key string, dst *T) {
	raw, ok := m[key]
	if !ok {
		return
	}
	_ = json.Unmarshal(raw, dst) // best-effort: ignore decode errors
}
