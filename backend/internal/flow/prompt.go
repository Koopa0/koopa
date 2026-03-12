package flow

import _ "embed"

//go:embed prompts/review.txt
var reviewSystemPrompt string

//go:embed prompts/excerpt.txt
var excerptSystemPrompt string

//go:embed prompts/tags.txt
var tagsSystemPrompt string

//go:embed prompts/polish.txt
var polishSystemPrompt string

//go:embed prompts/digest.txt
var digestSystemPrompt string

//go:embed prompts/bookmark.txt
var bookmarkSystemPrompt string

//go:embed prompts/morning_brief.txt
var morningBriefSystemPrompt string

//go:embed prompts/weekly_review.txt
var weeklyReviewSystemPrompt string

//go:embed prompts/project_track.txt
var projectTrackSystemPrompt string

//go:embed prompts/content_strategy.txt
var contentStrategySystemPrompt string

//go:embed prompts/build_log.txt
var buildLogSystemPrompt string
