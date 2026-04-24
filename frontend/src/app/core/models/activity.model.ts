/** Cross-domain activity / changelog models. */

export type ActivityEntityType =
  | 'todo'
  | 'goal'
  | 'milestone'
  | 'project'
  | 'content'
  | 'bookmark'
  | 'note'
  | 'learning_attempt'
  | 'task'
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

export interface ChangelogEvent {
  id: string;
  timestamp: string;
  entity_type: ActivityEntityType;
  entity_id: string;
  change_kind: ActivityChangeKind;
  title: string;
  project: string | null;
  /**may be absent today. */
  actor?: string | null;
}

export interface ChangelogDay {
  date: string;
  event_count: number;
  events: ChangelogEvent[];
}

export interface ChangelogResponse {
  days: ChangelogDay[];
}
