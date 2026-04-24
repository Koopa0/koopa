import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { ActivityService } from '../../../core/services/activity.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import type {
  ActivityChangeKind,
  ActivityEntityType,
  ChangelogEvent,
  ChangelogResponse,
} from '../../../core/models/activity.model';

type EntityFilter = 'all' | ActivityEntityType;
type KindFilter = 'all' | ActivityChangeKind;

interface Chip<T extends string> {
  value: T;
  label: string;
}

const ENTITY_CHIPS: readonly Chip<EntityFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'content', label: 'Content' },
  { value: 'bookmark', label: 'Bookmark' },
  { value: 'note', label: 'Note' },
  { value: 'todo', label: 'Todo' },
  { value: 'goal', label: 'Goal' },
  { value: 'project', label: 'Project' },
  { value: 'task', label: 'Task' },
  { value: 'learning_hypothesis', label: 'Hypothesis' },
  { value: 'learning_attempt', label: 'Attempt' },
  { value: 'learning_session', label: 'Session' },
];

const KIND_CHIPS: readonly Chip<KindFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'created', label: 'Created' },
  { value: 'updated', label: 'Updated' },
  { value: 'state_changed', label: 'State' },
  { value: 'published', label: 'Published' },
  { value: 'completed', label: 'Completed' },
  { value: 'archived', label: 'Archived' },
];

/**
 * Routes from `entity_type` to the canonical detail surface. `%` is
 * replaced with the event's `entity_id`; targets without an id
 * placeholder land on the entity's list route.
 */
const ENTITY_ROUTE: Record<ActivityEntityType, string> = {
  content: '/admin/knowledge/content/%/edit',
  bookmark: '/admin/knowledge/bookmarks',
  note: '/admin/knowledge/notes',
  task: '/admin/coordination/tasks/%',
  goal: '/admin/commitment/goals/%',
  milestone: '/admin/commitment/goals',
  project: '/admin/commitment/projects/%',
  todo: '/admin/commitment/todos',
  learning_hypothesis: '/admin/learning/hypotheses/%',
  learning_attempt: '/admin/learning/hypotheses',
  learning_session: '/admin/learning',
  learning_plan_entry: '/admin/learning',
};

/**
 * Activity log — day-grouped changelog with entity_type and
 * change_kind filter chips. Row click routes to the canonical detail
 * surface for that entity.
 */
@Component({
  selector: 'app-activity-page',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './activity.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ActivityPageComponent {
  private readonly activityService = inject(ActivityService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly entityChips = ENTITY_CHIPS;
  protected readonly kindChips = KIND_CHIPS;

  protected readonly entityFilter = signal<EntityFilter>('all');
  protected readonly kindFilter = signal<KindFilter>('all');

  protected readonly resource = rxResource<
    ChangelogResponse,
    { entity: EntityFilter; kind: KindFilter }
  >({
    params: () => ({ entity: this.entityFilter(), kind: this.kindFilter() }),
    stream: ({ params }) =>
      this.activityService.changelog({
        entity_type: params.entity === 'all' ? undefined : params.entity,
        change_kind: params.kind === 'all' ? undefined : params.kind,
      }),
  });

  protected readonly days = computed(() => this.resource.value()?.days ?? []);
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
      crumbs: ['Coordination', 'Activity'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setEntityFilter(value: EntityFilter): void {
    this.entityFilter.set(value);
  }

  protected setKindFilter(value: KindFilter): void {
    this.kindFilter.set(value);
  }

  protected canOpen(event: ChangelogEvent): boolean {
    return !!ENTITY_ROUTE[event.entity_type];
  }

  protected openEvent(event: ChangelogEvent): void {
    const template = ENTITY_ROUTE[event.entity_type];
    if (!template) return;
    this.router.navigateByUrl(template.replace('%', event.entity_id));
  }

  protected kindDotClass(kind: ActivityChangeKind): string {
    switch (kind) {
      case 'created':
        return 'bg-sky-500';
      case 'updated':
        return 'bg-zinc-400';
      case 'state_changed':
        return 'bg-amber-400';
      case 'published':
        return 'bg-emerald-500';
      case 'completed':
        return 'bg-emerald-400';
      case 'archived':
        return 'bg-zinc-600';
    }
  }
}
