package notion

import (
	"encoding/json"
	"time"
)

// Page represents a Notion page object.
type Page struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	CreatedTime    time.Time              `json:"created_time"`
	LastEditedTime time.Time              `json:"last_edited_time"`
	URL            string                 `json:"url"`
	Properties     map[string]Property    `json:"properties"`
	Parent         Parent                 `json:"parent"`
	Icon           *Icon                  `json:"icon,omitempty"`
	Cover          *Cover                 `json:"cover,omitempty"`
}

// Property represents a page property (simplified for title extraction).
type Property struct {
	Type  string       `json:"type"`
	Title []RichText   `json:"title,omitempty"`
}

// Parent represents the parent of a page.
type Parent struct {
	Type       string `json:"type"`
	PageID     string `json:"page_id,omitempty"`
	DatabaseID string `json:"database_id,omitempty"`
	Workspace  bool   `json:"workspace,omitempty"`
}

// Icon represents a page icon.
type Icon struct {
	Type  string `json:"type"`
	Emoji string `json:"emoji,omitempty"`
}

// Cover represents a page cover.
type Cover struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
}

// Block represents a Notion block object.
type Block struct {
	Object         string    `json:"object"`
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	CreatedTime    time.Time `json:"created_time"`
	LastEditedTime time.Time `json:"last_edited_time"`
	HasChildren    bool      `json:"has_children"`

	// Block type-specific content
	Paragraph        *TextBlock `json:"paragraph,omitempty"`
	Heading1         *TextBlock `json:"heading_1,omitempty"`
	Heading2         *TextBlock `json:"heading_2,omitempty"`
	Heading3         *TextBlock `json:"heading_3,omitempty"`
	BulletedListItem *TextBlock `json:"bulleted_list_item,omitempty"`
	NumberedListItem *TextBlock `json:"numbered_list_item,omitempty"`
	Code             *CodeBlock `json:"code,omitempty"`
	Quote            *TextBlock `json:"quote,omitempty"`
	Callout          *Callout   `json:"callout,omitempty"`
	ToDo             *ToDoBlock `json:"to_do,omitempty"`
}

// TextBlock represents blocks with rich text content (paragraph, headings, lists, quote).
type TextBlock struct {
	RichText []RichText `json:"rich_text"`
	Color    string     `json:"color,omitempty"`
}

// CodeBlock represents a code block.
type CodeBlock struct {
	RichText []RichText `json:"rich_text"`
	Language string     `json:"language"`
	Caption  []RichText `json:"caption,omitempty"`
}

// Callout represents a callout block.
type Callout struct {
	RichText []RichText `json:"rich_text"`
	Icon     *Icon      `json:"icon,omitempty"`
	Color    string     `json:"color,omitempty"`
}

// ToDoBlock represents a to-do block.
type ToDoBlock struct {
	RichText []RichText `json:"rich_text"`
	Checked  bool       `json:"checked"`
	Color    string     `json:"color,omitempty"`
}

// RichText represents a rich text object.
type RichText struct {
	Type        string       `json:"type"`
	PlainText   string       `json:"plain_text"`
	Href        string       `json:"href,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
	Text        *Text        `json:"text,omitempty"`
}

// Annotations represents text formatting.
type Annotations struct {
	Bold          bool   `json:"bold"`
	Italic        bool   `json:"italic"`
	Strikethrough bool   `json:"strikethrough"`
	Underline     bool   `json:"underline"`
	Code          bool   `json:"code"`
	Color         string `json:"color"`
}

// Text represents the text content.
type Text struct {
	Content string `json:"content"`
	Link    *Link  `json:"link,omitempty"`
}

// Link represents a hyperlink.
type Link struct {
	URL string `json:"url"`
}

// SearchResponse represents the response from the search endpoint.
type SearchResponse struct {
	Object     string            `json:"object"`
	Results    []json.RawMessage `json:"results"` // Union type: can be Page or Database
	NextCursor string            `json:"next_cursor,omitempty"`
	HasMore    bool              `json:"has_more"`
}

// BlockChildrenResponse represents the response from get block children endpoint.
type BlockChildrenResponse struct {
	Object     string  `json:"object"`
	Results    []Block `json:"results"`
	NextCursor string  `json:"next_cursor,omitempty"`
	HasMore    bool    `json:"has_more"`
}

// SearchRequest represents the request body for search.
type SearchRequest struct {
	Query      string        `json:"query,omitempty"`
	Filter     *SearchFilter `json:"filter,omitempty"`
	Sort       *SearchSort   `json:"sort,omitempty"`
	StartCursor string       `json:"start_cursor,omitempty"`
	PageSize   int           `json:"page_size,omitempty"`
}

// SearchFilter filters search results by object type.
type SearchFilter struct {
	Property string `json:"property"`
	Value    string `json:"value"`
}

// SearchSort specifies sort order for search results.
type SearchSort struct {
	Direction string `json:"direction"` // "ascending" or "descending"
	Timestamp string `json:"timestamp"` // "last_edited_time"
}
