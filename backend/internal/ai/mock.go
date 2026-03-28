package ai

// PendingTask represents a task pending completion.
// Defined in the parent ai package so that task/store.go can reference it
// without importing the report sub-package.
type PendingTask struct {
	Title string
	Due   string // YYYY-MM-DD or empty
}

// ProjectCompletion holds a per-project completion count.
// Defined in the parent ai package so that task/store.go can reference it
// without importing the report sub-package.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// NewMockDigestGenerate returns a mock Flow for MOCK_MODE.
func NewMockDigestGenerate() Flow {
	return &mockFlow{
		name: "digest-generate",
		output: struct {
			Markdown string `json:"markdown"`
		}{Markdown: "## Mock Digest\n\nThis is a mock weekly digest."},
	}
}

// NewMockMorningBrief returns a mock Flow for MOCK_MODE.
func NewMockMorningBrief() Flow {
	return &mockFlow{
		name: "morning-brief",
		output: struct {
			Text string `json:"text"`
		}{Text: "Mock morning brief"},
	}
}

// NewMockWeeklyReview returns a mock Flow for MOCK_MODE.
func NewMockWeeklyReview() Flow {
	return &mockFlow{
		name: "weekly-review",
		output: struct {
			Text string `json:"text"`
		}{Text: "Mock weekly review"},
	}
}

// NewMockDailyDevLog returns a mock Flow for MOCK_MODE.
func NewMockDailyDevLog() Flow {
	return &mockFlow{
		name: "daily-dev-log",
		output: struct {
			Date     string `json:"date"`
			Markdown string `json:"markdown"`
			Events   int    `json:"events"`
		}{Date: "2026-03-17", Markdown: "# Daily Dev Log — Mock\n\nNo activity.", Events: 0},
	}
}

// NewMockProjectTrack returns a mock Flow for MOCK_MODE.
func NewMockProjectTrack() Flow {
	return &mockFlow{
		name: "project-track",
		output: struct {
			Text    string `json:"text"`
			Skipped bool   `json:"skipped"`
		}{Text: "Mock project track", Skipped: true},
	}
}

// NewMockBuildLog returns a mock Flow for MOCK_MODE.
func NewMockBuildLog() Flow {
	return &mockFlow{
		name: "build-log-generate",
		output: struct {
			ContentID string `json:"content_id"`
			Title     string `json:"title"`
		}{ContentID: "mock-id", Title: "Mock build log"},
	}
}

// NewMockContentStrategy returns a mock Flow for MOCK_MODE.
func NewMockContentStrategy() Flow {
	return &mockFlow{
		name:   "content-strategy",
		output: ContentStrategyOutput{Text: "Mock content strategy"},
	}
}
