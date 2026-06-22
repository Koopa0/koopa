/** Cross-domain activity / changelog models. */

export type ActivityEntityType =
  | 'todo'
  | 'goal'
  | 'milestone'
  | 'project'
  | 'content'
  | 'learning_attempt'
  | 'learning_hypothesis'
  | 'learning_plan_entry'
  | 'learning_session';

export type ActivityChangeKind =
  | 'created'
  | 'updated'
  | 'state_changed'
  | 'published'
  | 'completed'
  | 'archived';

/**
 * One changelog row. Mirrors internal/activity/activity.go::ChangelogEvent:
 * `actor` is always on the wire (non-null); `entity_id`, `title`, and
 * `project` are `omitempty` and may be absent.
 */
export interface ChangelogEvent {
  id: string;
  timestamp: string;
  entity_type: ActivityEntityType;
  entity_id?: string;
  change_kind: ActivityChangeKind;
  title?: string;
  project?: string | null;
  actor: string;
}

export interface ChangelogDay {
  date: string;
  event_count: number;
  events: ChangelogEvent[];
}

export interface ChangelogResponse {
  days: ChangelogDay[];
}
