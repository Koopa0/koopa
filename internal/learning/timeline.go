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
	Slug                 string                `json:"slug"`
	Title                string                `json:"title"`
	ContentType          string                `json:"content_type"`
	Result               string                `json:"result,omitempty"`
	Tags                 []string              `json:"tags"`
	LearningType         string                `json:"learning_type,omitempty"`
	WeaknessObservations []WeaknessObservation `json:"weakness_observations,omitempty"`
	KeyConcepts          []KeyConcept          `json:"key_concepts,omitempty"`
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

	for _, e := range entries {
		dateStr := e.CreatedAt.Format(time.DateOnly)
		te := buildTimelineEntry(e)
		dayMap[dateStr] = append(dayMap[dateStr], te)

		if e.ProjectSlug != "" {
			projectCounts[e.ProjectSlug]++
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
func buildTimelineEntry(e content.RichTagEntry) TimelineEntry {
	te := TimelineEntry{
		Slug:        e.Slug,
		Title:       e.Title,
		ContentType: "til",
		Result:      extractResultTag(e.Tags),
		Tags:        e.Tags,
	}

	if len(e.AIMetadata) == 0 {
		return te
	}

	// Parse learning_type and structured fields from ai_metadata.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(e.AIMetadata, &m); err != nil {
		return te
	}

	if raw, ok := m["learning_type"]; ok {
		var lt string
		if err := json.Unmarshal(raw, &lt); err == nil {
			te.LearningType = lt
		}
	}

	if raw, ok := m["weakness_observations"]; ok {
		var obs []WeaknessObservation
		if err := json.Unmarshal(raw, &obs); err == nil {
			te.WeaknessObservations = obs
		}
	}

	if raw, ok := m["key_concepts"]; ok {
		var kc []KeyConcept
		if err := json.Unmarshal(raw, &kc); err == nil {
			te.KeyConcepts = kc
		}
	}

	return te
}
