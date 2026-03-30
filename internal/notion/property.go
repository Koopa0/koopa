package notion

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/tag"
)

// TitleProperty extracts the plain text from a Notion title property.
func TitleProperty(raw json.RawMessage) string {
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

// RichTextProperty extracts plain text from a Notion rich_text property.
func RichTextProperty(raw json.RawMessage) string {
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

// StatusProperty extracts the status name from a Notion status property.
func StatusProperty(raw json.RawMessage) string {
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

// SelectProperty extracts the select name from a Notion select property.
func SelectProperty(raw json.RawMessage) string {
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

// DateProperty extracts the start date from a Notion date property.
func DateProperty(raw json.RawMessage) *time.Time {
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

// CheckboxProperty extracts a boolean from a Notion checkbox property.
func CheckboxProperty(raw json.RawMessage) bool {
	var prop struct {
		Checkbox bool `json:"checkbox"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		return false
	}
	return prop.Checkbox
}

// NumberProperty extracts an integer from a Notion number property.
// Returns nil if the property is missing, null, or not a number.
func NumberProperty(raw json.RawMessage) *int32 {
	var prop struct {
		Number *float64 `json:"number"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil || prop.Number == nil {
		return nil
	}
	v := int32(*prop.Number)
	return &v
}

// RelationProperty extracts the first relation page ID from a Notion relation property.
func RelationProperty(raw json.RawMessage) string {
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

// Slugify converts a title to a URL-safe slug.
// Delegates to the canonical tag.Slugify implementation.
func Slugify(title string) string { return tag.Slugify(title) }
