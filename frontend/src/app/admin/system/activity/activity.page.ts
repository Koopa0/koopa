import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { ActivityService } from '../../../core/services/activity.service';
import { AgentService } from '../../../core/services/agent.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import type {
  ActivityChangeKind,
  ActivityEntityType,
  ChangelogEvent,
  ChangelogResponse,
} from '../../../core/models/activity.model';
import type { Agent } from '../../../core/models/workbench.model';

type EntityFilter = 'all' | ActivityEntityType;

interface Chip<T extends string> {
  value: T;
  label: string;
}

const ENTITY_CHIPS: readonly Chip<EntityFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'content', label: 'Content' },
  { value: 'note', label: 'Note' },
  { value: 'todo', label: 'Todo' },
  { value: 'goal', label: 'Goal' },
  { value: 'project', label: 'Project' },
  { value: 'learning_hypothesis', label: 'Hypothesis' },
  { value: 'learning_attempt', label: 'Attempt' },
  { value: 'learning_session', label: 'Session' },
];

/**
 * Routes from `entity_type` to the canonical detail surface. `%` is
 * replaced with the event's `entity_id`; targets without an id
 * placeholder land on the entity's list route.
 */
const ENTITY_ROUTE: Record<ActivityEntityType, string> = {
  content: '/admin/knowledge/content/%/edit',
  note: '/admin/knowledge/notes',
  goal: '/admin/commitment/goals/%',
  milestone: '/admin/commitment/goals',
  project: '/admin/commitment/projects/%',
  todo: '/admin/daily/todos',
  learning_hypothesis: '/admin/learning/hypotheses/%',
  learning_attempt: '/admin/learning/hypotheses',
  learning_session: '/admin/learning',
  learning_plan_entry: '/admin/learning',
};

/**
 * Activity log — day-grouped changelog with an entity-type filter (sent to
 * the backend as `source`) and a by-actor filter (sent as `actor`, the
 * backend's comma-separated allowlist param). Change kind is shown per
 * event but is not a server-side filter — the changelog endpoint has no
 * change-kind param. Row click routes to the canonical detail surface for
 * that entity.
 */
@Component({
  selector: 'app-activity-page',
  imports: [DatePipe],
  templateUrl: './activity.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ActivityPageComponent {
  private readonly activityService = inject(ActivityService);
  private readonly agentService = inject(AgentService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly entityChips = ENTITY_CHIPS;

  // Actor chips are sourced from the registry (name = filter value, the
  // backend's comma-separated `actor` allowlist; display_name = label) so
  // the filter stays in lock-step with the real agent roster.
  private readonly agents = toSignal(this.agentService.list(), {
    initialValue: [] as Agent[],
  });
  protected readonly actorChips = computed<Chip<string>[]>(() => [
    { value: '', label: 'All' },
    ...this.agents().map((a) => ({ value: a.name, label: a.display_name })),
  ]);

  protected readonly entityFilter = signal<EntityFilter>('all');
  protected readonly actorFilter = signal<string>('');

  protected readonly resource = rxResource<
    ChangelogResponse,
    { entity: EntityFilter; actor: string }
  >({
    params: () => ({ entity: this.entityFilter(), actor: this.actorFilter() }),
    stream: ({ params }) =>
      this.activityService.changelog({
        source: params.entity === 'all' ? undefined : params.entity,
        actor: params.actor === '' ? undefined : params.actor,
      }),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). The value is an
  // envelope, so guard the source then read `.days`.
  protected readonly days = computed(() =>
    this.resource.hasValue() ? this.resource.value().days : [],
  );
  protected readonly total = computed(() =>
    this.days().reduce((sum, d) => sum + d.event_count, 0),
  );
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && this.days().length === 0,
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  constructor() {
    this.topbar.set({
      title: 'Activity',
      crumbs: ['System', 'Activity'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setEntityFilter(value: EntityFilter): void {
    this.entityFilter.set(value);
  }

  protected setActorFilter(value: string): void {
    this.actorFilter.set(value);
  }

  protected canOpen(event: ChangelogEvent): boolean {
    const template = ENTITY_ROUTE[event.entity_type];
    if (!template) return false;
    // Templates with an id placeholder need a concrete entity_id; without
    // one (entity_id is omitempty on the wire) the row is not openable.
    return !template.includes('%') || !!event.entity_id;
  }

  protected openEvent(event: ChangelogEvent): void {
    const template = ENTITY_ROUTE[event.entity_type];
    if (!template) return;
    if (template.includes('%')) {
      if (!event.entity_id) return;
      this.router.navigateByUrl(template.replace('%', event.entity_id));
      return;
    }
    this.router.navigateByUrl(template);
  }

  protected kindDotClass(kind: ActivityChangeKind): string {
    switch (kind) {
      case 'created':
        return 'bg-brand';
      case 'updated':
        return 'bg-fg-subtle';
      case 'state_changed':
        return 'bg-warn';
      case 'published':
        return 'bg-success';
      case 'completed':
        return 'bg-success';
      case 'archived':
        return 'bg-fg-faint';
    }
  }
}
