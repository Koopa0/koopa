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
  | 'archive'
  | 'withdraw'
  | 'restore';

interface RailStep {
  status: ContentStatus;
  state: 'done' | 'active' | 'future';
}

interface RailAction {
  id: ContentLifecycleAction;
  label: string;
  primary: boolean;
}

const PUBLICATION_STATUS_ORDER: readonly ContentStatus[] = [
  'draft',
  'review',
  'changes_requested',
  'published',
];

/** Legal transition buttons offered for each current status. */
const ACTIONS_BY_STATUS: Record<ContentStatus, readonly RailAction[]> = {
  draft: [
    { id: 'submit-for-review', label: 'Submit for review', primary: false },
    { id: 'publish', label: 'Publish', primary: true },
  ],
  review: [
    { id: 'send-back', label: 'Send back', primary: false },
    { id: 'revert-to-draft', label: 'Revert to draft', primary: false },
    { id: 'publish', label: 'Publish', primary: true },
  ],
  changes_requested: [
    { id: 'revert-to-draft', label: 'Revert to draft', primary: false },
    { id: 'archive', label: 'Archive', primary: false },
  ],
  published: [],
  archived: [],
};

/**
 * Vertical lifecycle rail for the content editor sidebar. The publication
 * path ends at published; archived is a separate terminal disposal state for
 * never-published work and therefore renders alone rather than pretending a
 * publication passed through it.
 *
 * Publishing is a human-only action server-side and requires a source-bound
 * snapshot. The rail hides promotion actions for legacy unbound rows and
 * surfaces the human-only gate while a bound row sits in review.
 */
@Component({
  selector: 'app-content-lifecycle-rail',
  templateUrl: './lifecycle-rail.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContentLifecycleRailComponent {
  readonly status = input.required<ContentStatus>();
  readonly busy = input(false);
  readonly sourceBound = input(true);
  /** Current exposure for the historically published snapshot. */
  readonly isPublic = input(true);
  readonly action = output<ContentLifecycleAction>();

  protected readonly steps = computed<RailStep[]>(() => {
    if (this.status() === 'archived') {
      return [{ status: 'archived', state: 'active' }];
    }
    const current = PUBLICATION_STATUS_ORDER.indexOf(this.status());
    return PUBLICATION_STATUS_ORDER.map((status, i) => ({
      status,
      state: i < current ? 'done' : i === current ? 'active' : 'future',
    }));
  });

  protected readonly actions = computed<readonly RailAction[]>(() => {
    if (this.status() === 'published') {
      return this.isPublic()
        ? [{ id: 'withdraw', label: 'Withdraw', primary: false }]
        : [{ id: 'restore', label: 'Restore', primary: true }];
    }
    const actions = ACTIONS_BY_STATUS[this.status()];
    if (this.sourceBound()) return actions;
    return actions.filter(
      (action) => action.id !== 'publish' && action.id !== 'submit-for-review',
    );
  });

  protected readonly showPublishGate = computed(
    () => this.status() === 'review' && this.sourceBound(),
  );

  protected run(id: ContentLifecycleAction): void {
    if (this.busy()) return;
    this.action.emit(id);
  }
}
