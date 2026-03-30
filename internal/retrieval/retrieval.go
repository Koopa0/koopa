// Package retrieval provides spaced retrieval scheduling using a simplified SM-2 algorithm.
// Each retrieval attempt records a self-test result on a (content, tag) pair and computes
// the next review date. The retrieval queue surfaces items that are due for review.
package retrieval

import (
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
)

// Quality constants for self-test results.
const (
	QualityEasy   = "easy"
	QualityHard   = "hard"
	QualityFailed = "failed"
)

// ValidQuality reports whether q is a valid quality value.
func ValidQuality(q string) bool {
	return q == QualityEasy || q == QualityHard || q == QualityFailed
}

// Attempt is a single retrieval self-test record.
type Attempt struct {
	ID           int64     `json:"id"`
	ContentID    uuid.UUID `json:"content_id"`
	Tag          *string   `json:"tag,omitempty"`
	Quality      string    `json:"quality"`
	IntervalDays int       `json:"interval_days"`
	EaseFactor   float64   `json:"ease_factor"`
	NextDue      string    `json:"next_due"`
	CreatedAt    time.Time `json:"created_at"`
}

// DueItem is an item that should be reviewed, enriched with content metadata.
type DueItem struct {
	ContentID     uuid.UUID       `json:"content_id"`
	Slug          string          `json:"slug"`
	Title         string          `json:"title"`
	Tag           *string         `json:"tag,omitempty"`
	Reason        string          `json:"reason"`
	LastQuality   string          `json:"last_quality,omitempty"`
	LastAttemptAt *time.Time      `json:"last_attempt_at,omitempty"`
	NextDue       *string         `json:"next_due,omitempty"`
	AIMetadata    json.RawMessage `json:"ai_metadata,omitempty"`
}

// SM2Result holds the computed scheduling values after one retrieval attempt.
type SM2Result struct {
	IntervalDays int     `json:"interval_days"`
	EaseFactor   float64 `json:"ease_factor"`
	NextDue      string  `json:"next_due"`
}

// easeFloor is the minimum ease factor to prevent intervals from shrinking too fast.
const easeFloor = 1.3

// SM2Calculate computes the next review interval using a simplified SM-2 algorithm.
// For first attempts (prevInterval=0), uses an initial interval table.
// For subsequent attempts, multiplies the previous interval by a quality-dependent factor.
func SM2Calculate(prevInterval int, prevEase float64, quality string, now time.Time) SM2Result {
	var newInterval int
	var newEase float64

	if prevInterval == 0 {
		// First attempt: initial interval table.
		switch quality {
		case QualityEasy:
			newInterval = 3
		case QualityHard:
			newInterval = 1
		case QualityFailed:
			newInterval = 1
		}
		newEase = prevEase // First attempt doesn't adjust ease.
	} else {
		switch quality {
		case QualityEasy:
			newInterval = max(int(math.Round(float64(prevInterval)*prevEase)), prevInterval+1)
			newEase = prevEase + 0.15
		case QualityHard:
			newInterval = max(int(math.Round(float64(prevInterval)*1.2)), prevInterval+1)
			newEase = max(prevEase-0.15, easeFloor)
		case QualityFailed:
			newInterval = 1
			newEase = max(prevEase-0.20, easeFloor)
		}
	}

	nextDue := now.AddDate(0, 0, newInterval)
	return SM2Result{
		IntervalDays: newInterval,
		EaseFactor:   newEase,
		NextDue:      nextDue.Format(time.DateOnly),
	}
}
