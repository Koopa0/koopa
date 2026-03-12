package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/koopa0/blog-backend/internal/flow"
)

// TaskDB queries pending tasks from a Notion database.
type TaskDB struct {
	client     *Client
	databaseID string
}

// NewTaskDB returns a TaskDB for the given Notion database.
func NewTaskDB(client *Client, databaseID string) *TaskDB {
	return &TaskDB{client: client, databaseID: databaseID}
}

// PendingTasks queries tasks where Status != "Done" from the Notion database.
func (t *TaskDB) PendingTasks(ctx context.Context) ([]flow.PendingTask, error) {
	filter := json.RawMessage(`{
		"property": "Status",
		"status": {
			"does_not_equal": "Done"
		}
	}`)

	results, err := t.client.QueryDataSource(ctx, t.databaseID, filter)
	if err != nil {
		return nil, fmt.Errorf("querying notion tasks: %w", err)
	}

	tasks := make([]flow.PendingTask, 0, len(results))
	for _, r := range results {
		title := titleProperty(r.Properties["Name"])
		if title == "" {
			title = titleProperty(r.Properties["Title"])
		}
		if title == "" {
			continue
		}

		var due string
		if d := dateProperty(r.Properties["Due"]); d != nil {
			due = d.Format(time.DateOnly)
		}

		tasks = append(tasks, flow.PendingTask{
			Title: title,
			Due:   due,
		})
	}

	return tasks, nil
}
