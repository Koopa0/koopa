import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
} from '@angular/core';
import type { ContentStatus } from '../../../../core/models/api.model';

/** Lifecycle transition verbs the rail can request from its host. */
export type ContentLifecycleAction =
  | 'submit-for-review'
  | 'publish'
  | 'send-back'
  | 'revert-to-draft'
  | 'archive';

interface RailStep {
  status: ContentStatus;
  state: 'done' | 'active' | 'future';
}

interface RailAction {
  id: ContentLifecycleAction;
  label: string;
  primary: boolean;
}

const STATUS_ORDER: readonly ContentStatus[] = [
  'draft',
  'review',
  'changes_requested',
  'published',
  'archived',
];

/** Legal transition buttons offered for each current status. */
const ACTIONS_BY_STATUS: Record<ContentStatus, readonly RailAction[]> = {
  draft: [{ id: 'submit-for-review', label: 'Submit for review', primary: true }],
  review: [
    { id: 'send-back', label: 'Send back', primary: false },
    { id: 'revert-to-draft', label: 'Revert to draft', primary: false },
    { id: 'publish', label: 'Publish', primary: true },
  ],
  changes_requested: [
    { id: 'revert-to-draft', label: 'Revert to draft', primary: false },
    { id: 'archive', label: 'Archive', primary: false },
  ],
  published: [{ id: 'archive', label: 'Archive', primary: false }],
  archived: [{ id: 'revert-to-draft', label: 'Revert to draft', primary: false }],
};

/**
 * Vertical lifecycle rail for the content editor sidebar: the four
 * stages draft → review → published → archived rendered as a stepper
 * (past = check, current = dot, future = empty), with the legal
 * transitions for the current status as buttons underneath.
 *
 * Publishing is a human-only action server-side; the rail surfaces the
 * gate as a caption while the status sits in review.
 */
@Component({
  selector: 'app-content-lifecycle-rail',
  templateUrl: './lifecycle-rail.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContentLifecycleRailComponent {
  readonly status = input.required<ContentStatus>();
  readonly busy = input(false);
  readonly action = output<ContentLifecycleAction>();

  protected readonly steps = computed<RailStep[]>(() => {
    const current = STATUS_ORDER.indexOf(this.status());
    return STATUS_ORDER.map((status, i) => ({
      status,
      state: i < current ? 'done' : i === current ? 'active' : 'future',
    }));
  });

  protected readonly actions = computed<readonly RailAction[]>(
    () => ACTIONS_BY_STATUS[this.status()],
  );

  protected readonly showPublishGate = computed(
    () => this.status() === 'review',
  );

  protected run(id: ContentLifecycleAction): void {
    if (this.busy()) return;
    this.action.emit(id);
  }
}
