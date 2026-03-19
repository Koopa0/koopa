package notion

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
)

// titleProperty extracts the plain text from a Notion title property.
func titleProperty(raw json.RawMessage) string {
	var prop struct {
		Title []struct {
			PlainText string `json:"plain_text"`
		} `json:"title"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		return ""
	}
	var parts []string
	for _, t := range prop.Title {
		parts = append(parts, t.PlainText)
	}
	return strings.Join(parts, "")
}

// richTextProperty extracts plain text from a Notion rich_text property.
func richTextProperty(raw json.RawMessage) string {
	var prop struct {
		RichText []struct {
			PlainText string `json:"plain_text"`
		} `json:"rich_text"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		return ""
	}
	var parts []string
	for _, t := range prop.RichText {
		parts = append(parts, t.PlainText)
	}
	return strings.Join(parts, "")
}

// statusProperty extracts the status name from a Notion status property.
func statusProperty(raw json.RawMessage) string {
	var prop struct {
		Status *struct {
			Name string `json:"name"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || prop.Status == nil {
		return ""
	}
	return prop.Status.Name
}

// selectProperty extracts the select name from a Notion select property.
func selectProperty(raw json.RawMessage) string {
	var prop struct {
		Select *struct {
			Name string `json:"name"`
		} `json:"select"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || prop.Select == nil {
		return ""
	}
	return prop.Select.Name
}

// dateProperty extracts the start date from a Notion date property.
func dateProperty(raw json.RawMessage) *time.Time {
	var prop struct {
		Date *struct {
			Start string `json:"start"`
		} `json:"date"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || prop.Date == nil || prop.Date.Start == "" {
		return nil
	}
	// try full datetime first, then date-only
	if t, err := time.Parse(time.RFC3339, prop.Date.Start); err == nil {
		return &t
	}
	if t, err := time.Parse("2006-01-02", prop.Date.Start); err == nil {
		return &t
	}
	return nil
}

// checkboxProperty extracts a boolean from a Notion checkbox property.
func checkboxProperty(raw json.RawMessage) bool {
	var prop struct {
		Checkbox bool `json:"checkbox"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		return false
	}
	return prop.Checkbox
}

// numberProperty extracts an integer from a Notion number property.
// Returns nil if the property is missing, null, or not a number.
func numberProperty(raw json.RawMessage) *int32 {
	var prop struct {
		Number *float64 `json:"number"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || prop.Number == nil {
		return nil
	}
	v := int32(*prop.Number)
	return &v
}

// relationProperty extracts the first relation page ID from a Notion relation property.
func relationProperty(raw json.RawMessage) string {
	var prop struct {
		Relation []struct {
			ID string `json:"id"`
		} `json:"relation"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || len(prop.Relation) == 0 {
		return ""
	}
	return prop.Relation[0].ID
}

// mapNotionProjectStatus maps a Notion UB 3.0 project status to the local enum.
func mapNotionProjectStatus(notionStatus string) project.Status {
	switch notionStatus {
	case "Planned":
		return project.StatusPlanned
	case "On Hold":
		return project.StatusOnHold
	case "Doing":
		return project.StatusInProgress
	case "Ongoing":
		return project.StatusMaintained
	case "Done":
		return project.StatusCompleted
	default:
		return project.StatusInProgress
	}
}

// mapNotionGoalStatus maps a Notion goal status to the local enum.
// UB 3.0 uses: Dream, Active, Achieved (mapped from status groups: to_do, in_progress, complete).
func mapNotionGoalStatus(notionStatus string) goal.Status {
	switch notionStatus {
	case "Not Started", "Dream":
		return goal.StatusNotStarted
	case "In Progress", "Doing", "Active":
		return goal.StatusInProgress
	case "Done", "Achieved":
		return goal.StatusDone
	case "Abandoned":
		return goal.StatusAbandoned
	default:
		return goal.StatusNotStarted
	}
}

// mapNotionTaskStatus maps a Notion task status to the local enum.
func mapNotionTaskStatus(notionStatus string) task.Status {
	switch notionStatus {
	case "Not Started", "To Do":
		return task.StatusTodo
	case "In Progress", "Doing":
		return task.StatusInProgress
	case "Done":
		return task.StatusDone
	default:
		return task.StatusTodo
	}
}

// Slugify converts a title to a URL-safe slug.
func Slugify(title string) string {
	s := strings.ToLower(title)
	s = strings.TrimSpace(s)

	var result []rune
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			result = append(result, r)
			prevDash = false
		case r == '-' || r == '_' || r == ' ':
			if !prevDash && len(result) > 0 {
				result = append(result, '-')
				prevDash = true
			}
		case r > 127:
			// keep CJK and other unicode characters
			result = append(result, r)
			prevDash = false
		}
	}

	// trim trailing dash
	if len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}

	return string(result)
}
