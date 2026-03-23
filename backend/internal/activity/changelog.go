package activity

// GroupChangelog groups sorted events (newest-first) by calendar date.
// Returns days newest-first, each containing events newest-first.
func GroupChangelog(events []Event) []ChangelogDay {
	if len(events) == 0 {
		return []ChangelogDay{}
	}

	var days []ChangelogDay
	var cur *ChangelogDay

	for eIdx := range events {
		e := events[eIdx]
		date := e.Timestamp.Format("2006-01-02")
		if cur == nil || cur.Date != date {
			if cur != nil {
				days = append(days, *cur)
			}
			cur = &ChangelogDay{Date: date}
		}
		cur.EventCount++
		cur.Events = append(cur.Events, ChangelogEvent{
			Source:    e.Source,
			EventType: e.EventType,
			Project:   e.Project,
			Title:     e.Title,
			Timestamp: e.Timestamp,
		})
	}
	if cur != nil {
		days = append(days, *cur)
	}

	return days
}
