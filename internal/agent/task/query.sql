-- name: CreateTask :one
-- Insert a new task in 'submitted' state. The chk_tasks_no_self_assignment
-- and chk_task_title_not_blank CHECKs run here; CHECK violations bubble up
-- as PostgreSQL 23514 and are mapped to ErrInvalidInput in the store.
INSERT INTO tasks (created_by, assignee, title, deadline, priority, metadata)
VALUES (@created_by, @assignee, @title, sqlc.narg('deadline'), sqlc.narg('priority'), @metadata)
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: TaskByID :one
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks WHERE id = @id;

-- name: AcceptTask :one
-- Transition a task from submitted → working. The chk_tasks_state_timestamps
-- CHECK enforces that accepted_at is set together with state=working; any
-- attempt to accept a non-submitted task triggers a CHECK violation, which
-- the store maps to ErrConflict.
UPDATE tasks
SET state = 'working', accepted_at = now()
WHERE id = @id AND state = 'submitted'
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: TransitionTaskToCompleted :one
-- Flip a task from working → completed. The trg_tasks_completion_requires_outputs
-- trigger fires here: it counts response messages and artifacts on this
-- task_id and raises P0001 if either is zero. Callers MUST run this in the
-- same transaction as the AppendMessage + AddArtifact inserts so the trigger
-- sees them.
UPDATE tasks
SET state = 'completed', completed_at = now()
WHERE id = @id AND state = 'working'
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: CancelTask :one
-- Mark a task canceled. Allowed from submitted or working; the
-- chk_tasks_state_timestamps CHECK guards the (state, canceled_at) pair.
UPDATE tasks
SET state = 'canceled', canceled_at = now()
WHERE id = @id AND state IN ('submitted', 'working')
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: RequestRevisionTask :one
-- Transition completed → revision_requested. Only the task creator (source)
-- should call this after reviewing the deliverable. Sets revision_requested_at.
UPDATE tasks
SET state = 'revision_requested', revision_requested_at = now()
WHERE id = @id AND state = 'completed'
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: ReacceptTask :one
-- Transition revision_requested → working. The assignee picks up the revision.
-- Clears completed_at and revision_requested_at so the task can be re-completed.
UPDATE tasks
SET state = 'working', completed_at = NULL, revision_requested_at = NULL
WHERE id = @id AND state = 'revision_requested'
RETURNING id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata;

-- name: OpenTasksForAssignee :many
-- Tasks where this agent is the assignee and state is submitted, working,
-- or revision_requested. Includes revision_requested so agents see tasks
-- needing revision in their queue. Newest first.
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE assignee = @assignee AND state IN ('submitted', 'working', 'revision_requested')
ORDER BY submitted_at DESC
LIMIT @max_results;

-- name: OpenTasksForCreator :many
-- Tasks the calling agent submitted that are still open (submitted, working,
-- or revision_requested).
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE created_by = @created_by AND state IN ('submitted', 'working', 'revision_requested')
ORDER BY submitted_at DESC
LIMIT @max_results;

-- name: LockTaskForAppend :exec
-- Acquire a row-level lock on the parent tasks row before appending a
-- message. Must be called inside the same transaction as the subsequent
-- AppendTaskMessage so the lock scope covers the MAX(position) read and
-- INSERT. Serializes concurrent appenders on the same task; other tasks
-- remain parallel. Returns no data; the caller only cares that the lock
-- succeeded before computing position.
SELECT id FROM tasks WHERE id = @task_id FOR UPDATE;

-- name: AppendTaskMessage :one
-- Append a message to a task, computing position = MAX(position) + 1
-- atomically. Caller MUST have called LockTaskForAppend in the same
-- transaction first; that lock serializes concurrent appenders so the
-- scalar subquery for position is stable at INSERT time. Without the
-- lock, two appenders at READ COMMITTED can both read the same MAX and
-- one will hit UNIQUE(task_id, position) and fail.
-- chk_task_messages_parts_count and chk_task_messages_parts_size enforce
-- the 1..16 parts and ≤32 KB bounds at the DB layer; CHECK violations map
-- to ErrInvalidInput.
INSERT INTO task_messages (task_id, role, position, parts)
VALUES (
    @task_id,
    @role::message_role,
    COALESCE(
        (SELECT MAX(position) + 1 FROM task_messages WHERE task_id = @task_id),
        0
    ),
    @parts
)
RETURNING id, task_id, role, position, parts, created_at;

-- name: TaskMessages :many
-- All messages on a task, in conversation order.
SELECT id, task_id, role, position, parts, created_at
FROM task_messages
WHERE task_id = @task_id
ORDER BY position ASC;

-- name: AllOpenTasks :many
-- All submitted+working+revision_requested tasks across all agents.
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE state IN ('submitted', 'working', 'revision_requested')
ORDER BY submitted_at DESC
LIMIT @max_results;

-- name: RecentResolvedTasks :many
-- Recently completed or canceled tasks. Orders by COALESCE of terminal timestamps.
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE state IN ('completed', 'canceled')
ORDER BY COALESCE(completed_at, canceled_at) DESC
LIMIT @max_results;

-- name: TasksPaged :many
-- Admin paginated list with optional state filter.
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE (sqlc.narg('state')::task_state IS NULL OR state = sqlc.narg('state')::task_state)
ORDER BY submitted_at DESC
LIMIT @page_limit OFFSET @page_offset;

-- name: TasksPagedCount :one
SELECT COUNT(*) FROM tasks
WHERE (sqlc.narg('state')::task_state IS NULL OR state = sqlc.narg('state')::task_state);

-- name: OpenTasksPaged :many
-- Admin paginated open tasks (submitted + working + revision_requested).
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE state IN ('submitted', 'working', 'revision_requested')
ORDER BY submitted_at DESC
LIMIT @page_limit OFFSET @page_offset;

-- name: OpenTasksPagedCount :one
SELECT COUNT(*) FROM tasks
WHERE state IN ('submitted', 'working', 'revision_requested');

-- name: CompletedTasksPaged :many
-- Admin paginated completed tasks.
SELECT id, created_by, assignee, title, state, deadline, priority, submitted_at, accepted_at, completed_at, canceled_at, revision_requested_at, metadata
FROM tasks
WHERE state = 'completed'
ORDER BY completed_at DESC NULLS LAST
LIMIT @page_limit OFFSET @page_offset;

-- name: CompletedTasksPagedCount :one
SELECT COUNT(*) FROM tasks
WHERE state = 'completed';
