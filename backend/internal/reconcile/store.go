package reconcile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/koopa0/blog-backend/internal/db"
)

// RunRecord is the API-facing representation of a reconcile run.
type RunRecord struct {
	ID                int64           `json:"id"`
	StartedAt         time.Time       `json:"started_at"`
	CompletedAt       *time.Time      `json:"completed_at,omitempty"`
	ObsidianMissing   int             `json:"obsidian_missing"`
	ObsidianOrphaned  int             `json:"obsidian_orphaned"`
	NotionProjMissing int             `json:"notion_proj_missing"`
	NotionProjOrphan  int             `json:"notion_proj_orphan"`
	NotionGoalMissing int             `json:"notion_goal_missing"`
	NotionGoalOrphan  int             `json:"notion_goal_orphan"`
	TotalDrift        int             `json:"total_drift"`
	ErrorCount        int             `json:"error_count"`
	Errors            json.RawMessage `json:"errors,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
}

// Store provides database operations for reconcile runs.
type Store struct {
	q *db.Queries
}

// NewStore returns a reconcile Store.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// SaveRun persists a reconcile run result.
// All drift counts are bounded by the number of files/pages in the system
// (typically 0-50), well within int32 range.
func (s *Store) SaveRun(ctx context.Context, startedAt, completedAt time.Time, report *Report, errs []string) (int64, error) {
	totalDrift := len(report.ObsidianMissing) + len(report.ObsidianOrphaned) +
		len(report.ProjectsMissing) + len(report.ProjectsOrphaned) +
		len(report.GoalsMissing) + len(report.GoalsOrphaned)

	var errJSON json.RawMessage
	if len(errs) > 0 {
		if data, marshalErr := json.Marshal(errs); marshalErr == nil {
			errJSON = data
		}
		// best-effort: invalid UTF-8 in error strings would fail marshal
	}

	return s.q.InsertReconcileRun(ctx, db.InsertReconcileRunParams{
		StartedAt:         startedAt,
		CompletedAt:       &completedAt,
		ObsidianMissing:   int32(len(report.ObsidianMissing)),  //nolint:gosec // bounded by file count
		ObsidianOrphaned:  int32(len(report.ObsidianOrphaned)), //nolint:gosec // bounded by file count
		NotionProjMissing: int32(len(report.ProjectsMissing)),  //nolint:gosec // bounded by Notion page count
		NotionProjOrphan:  int32(len(report.ProjectsOrphaned)), //nolint:gosec // bounded by local project count
		NotionGoalMissing: int32(len(report.GoalsMissing)),     //nolint:gosec // bounded by Notion page count
		NotionGoalOrphan:  int32(len(report.GoalsOrphaned)),    //nolint:gosec // bounded by local goal count
		TotalDrift:        int32(totalDrift),                   //nolint:gosec // sum of above, still bounded
		ErrorCount:        int32(len(errs)),                    //nolint:gosec // bounded by error count per run
		Errors:            errJSON,
	})
}

// RecentRuns returns the most recent reconcile runs.
func (s *Store) RecentRuns(ctx context.Context, limit int) ([]RunRecord, error) {
	rows, err := s.q.RecentReconcileRuns(ctx, int32(limit)) //nolint:gosec // limit bounded to [1,100] by handler
	if err != nil {
		return nil, err
	}
	records := make([]RunRecord, len(rows))
	for i, r := range rows {
		records[i] = RunRecord{
			ID:                r.ID,
			StartedAt:         r.StartedAt,
			CompletedAt:       r.CompletedAt,
			ObsidianMissing:   int(r.ObsidianMissing),
			ObsidianOrphaned:  int(r.ObsidianOrphaned),
			NotionProjMissing: int(r.NotionProjMissing),
			NotionProjOrphan:  int(r.NotionProjOrphan),
			NotionGoalMissing: int(r.NotionGoalMissing),
			NotionGoalOrphan:  int(r.NotionGoalOrphan),
			TotalDrift:        int(r.TotalDrift),
			ErrorCount:        int(r.ErrorCount),
			Errors:            r.Errors,
			CreatedAt:         r.CreatedAt,
		}
	}
	return records, nil
}
