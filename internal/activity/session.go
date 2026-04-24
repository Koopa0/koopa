package activity

import (
	"slices"
	"time"
)

// sessionGap is the inactivity threshold that defines session boundaries.
const sessionGap = 30 * time.Minute

// Session represents a contiguous work session reconstructed from activity events.
type Session struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Duration   string    `json:"duration"`
	EventCount int       `json:"event_count"`
	Sources    []string  `json:"sources"`
	Projects   []string  `json:"projects"`
}

// GroupSessions groups sorted events (newest-first) into work sessions.
// A gap of 30+ minutes between consecutive events starts a new session.
func GroupSessions(events []Event) []Session {
	if len(events) == 0 {
		return []Session{}
	}

	// events are DESC — reverse to process chronologically
	n := len(events)
	reversed := make([]Event, n)
	for i := range events {
		reversed[n-1-i] = events[i]
	}

	var sessions []Session
	cur := newSessionBuilder(&reversed[0])

	for i := range reversed[1:] {
		if reversed[1+i].Timestamp.Sub(cur.end) >= sessionGap {
			sessions = append(sessions, cur.build())
			cur = newSessionBuilder(&reversed[1+i])
		} else {
			cur.add(&reversed[1+i])
		}
	}
	sessions = append(sessions, cur.build())

	for i, j := 0, len(sessions)-1; i < j; i, j = i+1, j-1 {
		sessions[i], sessions[j] = sessions[j], sessions[i]
	}
	return sessions
}

type sessionBuilder struct {
	start    time.Time
	end      time.Time
	count    int
	sources  map[string]struct{}
	projects map[string]struct{}
}

func newSessionBuilder(e *Event) *sessionBuilder {
	sb := &sessionBuilder{
		start:    e.Timestamp,
		end:      e.Timestamp,
		count:    1,
		sources:  map[string]struct{}{e.EntityType: {}},
		projects: map[string]struct{}{},
	}
	if e.Project != nil && *e.Project != "" {
		sb.projects[*e.Project] = struct{}{}
	}
	return sb
}

func (sb *sessionBuilder) add(e *Event) {
	if e.Timestamp.After(sb.end) {
		sb.end = e.Timestamp
	}
	sb.count++
	sb.sources[e.EntityType] = struct{}{}
	if e.Project != nil && *e.Project != "" {
		sb.projects[*e.Project] = struct{}{}
	}
}

func (sb *sessionBuilder) build() Session {
	return Session{
		Start:      sb.start,
		End:        sb.end,
		Duration:   sb.end.Sub(sb.start).Truncate(time.Minute).String(),
		EventCount: sb.count,
		Sources:    setToSlice(sb.sources),
		Projects:   setToSlice(sb.projects),
	}
}

func setToSlice(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	slices.Sort(s)
	return s
}
