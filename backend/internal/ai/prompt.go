package ai

import _ "embed"

//go:embed prompts/review.txt
var ReviewSystemPrompt string

//go:embed prompts/excerpt.txt
var ExcerptSystemPrompt string

//go:embed prompts/tags.txt
var TagsSystemPrompt string

//go:embed prompts/polish.txt
var PolishSystemPrompt string

//go:embed prompts/digest.txt
var DigestSystemPrompt string

//go:embed prompts/bookmark.txt
var bookmarkSystemPrompt string

//go:embed prompts/weekly_review.txt
var WeeklyReviewSystemPrompt string

//go:embed prompts/project_track.txt
var ProjectTrackSystemPrompt string

//go:embed prompts/content_strategy.txt
var contentStrategySystemPrompt string

//go:embed prompts/build_log.txt
var BuildLogSystemPrompt string

//go:embed prompts/daily_dev_log.txt
var DailyDevLogSystemPrompt string
