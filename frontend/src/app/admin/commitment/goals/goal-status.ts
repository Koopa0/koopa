import type { GoalStatus } from '../../../core/models';

/** Status chip recipe — *-bg surface + matching foreground token. */
export const GOAL_STATUS_CHIP_CLASS: Record<GoalStatus, string> = {
  not_started: 'bg-overlay text-fg-subtle',
  in_progress: 'bg-info-bg text-info',
  on_hold: 'bg-warn-bg text-warn',
  done: 'bg-success-bg text-success',
  abandoned: 'bg-overlay text-fg-faint',
};

/** Menu dot colors per status. */
export const GOAL_STATUS_DOT_CLASS: Record<GoalStatus, string> = {
  not_started: 'bg-fg-subtle',
  in_progress: 'bg-info',
  on_hold: 'bg-warn',
  done: 'bg-success',
  abandoned: 'bg-fg-faint',
};

/** Display labels (underscore → space). */
export const GOAL_STATUS_LABEL: Record<GoalStatus, string> = {
  not_started: 'not started',
  in_progress: 'in progress',
  on_hold: 'on hold',
  done: 'done',
  abandoned: 'abandoned',
};

// All 5 statuses are surfaced; legal transitions are enforced
// server-side. Illegal transitions come back as HTTP 400.
export const GOAL_STATUS_OPTIONS: readonly GoalStatus[] = [
  'not_started',
  'in_progress',
  'on_hold',
  'done',
  'abandoned',
];
