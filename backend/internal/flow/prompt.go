package flow

import _ "embed"

//go:embed prompts/review.txt
var reviewSystemPrompt string

//go:embed prompts/excerpt.txt
var excerptSystemPrompt string

//go:embed prompts/tags.txt
var tagsSystemPrompt string
