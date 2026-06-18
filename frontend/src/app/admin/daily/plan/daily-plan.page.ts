import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  linkedSignal,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import {
  CdkDrag,
  CdkDragHandle,
  CdkDropList,
  moveItemInArray,
} from '@angular/cdk/drag-drop';
import type { CdkDragDrop } from '@angular/cdk/drag-drop';
import { firstValueFrom } from 'rxjs';
import { CalendarCheck, ListPlus, LucideAngularModule } from 'lucide-angular';

import { EmptyStateComponent } from '../../../shared/components';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import {
  DailyPlanService,
  type DailyPlan,
  type DailyPlanEntry,
} from '../../../core/services/daily-plan.service';
import { TodoService, type TodoRow } from '../../../core/services/todo.service';
import {
  appendWriteItems,
  isLastPlanned,
  plannedEntries,
  removeWriteItems,
  unplannedCandidates,
  writeItemsFrom,
} from './daily-plan-view';

/**
 * Daily plan builder — the dedicated surface where Koopa composes today's
 * plan. Distinct from Today, which renders the committed plan with
 * advance-on-click; this page is the editor that produces that plan.
 *
 * It edits only the `planned` slice: drag to reorder, pick an un-planned
 * todo to add, remove an item. Every mutation goes through the atomic
 * daily-plan PUT (DailyPlanService.replace) which rewrites positions and
 * leaves done/deferred/dropped history untouched. The PUT rejects an empty
 * item list, so the last planned item can't be removed here — that belongs
 * to Today or day-close. After each write the page re-renders from the
 * server's returned plan, never a local guess.
 */
@Component({
  selector: 'app-daily-plan-page',
  imports: [
    DatePipe,
    LucideAngularModule,
    EmptyStateComponent,
    CdkDropList,
    CdkDrag,
    CdkDragHandle,
  ],
  templateUrl: './daily-plan.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class DailyPlanPageComponent {
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly todoService = inject(TodoService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly CalendarCheckIcon = CalendarCheck;
  protected readonly ListPlusIcon = ListPlus;

  private readonly planResource = rxResource<DailyPlan, void>({
    stream: () => this.dailyPlanService.today(),
  });

  // Candidate todos for the add picker. state=todo is the only plannable
  // state (inbox is rejected by the PUT); the view filters out any already
  // in the plan.
  private readonly todosResource = rxResource<TodoRow[], void>({
    stream: () => this.todoService.list({ state: 'todo' }),
  });

  /** Full plan as last returned by the server (all states, for history). */
  protected readonly plan = computed(() =>
    this.planResource.hasValue() ? this.planResource.value() : undefined,
  );

  /**
   * Local working copy of the planned slice; drag-reorder mutates it
   * optimistically, then a successful PUT resyncs it from the envelope.
   */
  protected readonly planned = linkedSignal<DailyPlanEntry[]>(() =>
    plannedEntries(this.plan()?.items ?? []),
  );

  protected readonly date = computed(() => this.plan()?.date ?? '');

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). planResource is
  // already guarded via plan() above.
  protected readonly candidates = computed(() =>
    unplannedCandidates(
      this.todosResource.hasValue() ? this.todosResource.value() : [],
      this.plan()?.items ?? [],
    ),
  );

  protected readonly isLoading = computed(
    () => this.planResource.status() === 'loading' && !this.planResource.hasValue(),
  );
  protected readonly isError = computed(
    () => this.planResource.status() === 'error',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && !this.isError() && this.planned().length === 0,
  );

  private readonly _busy = signal(false);
  protected readonly busy = this._busy.asReadonly();

  /** Whether the add picker is open. */
  private readonly _picking = signal(false);
  protected readonly picking = this._picking.asReadonly();

  constructor() {
    this.topbar.set({ title: 'Plan', crumbs: ['Daily', 'Plan'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected retry(): void {
    this.planResource.reload();
  }

  protected isLastPlanned(todoId: string): boolean {
    return isLastPlanned(this.planned(), todoId);
  }

  protected togglePicker(): void {
    this._picking.update((open) => !open);
  }

  /** Reorder: optimistic move, PUT the rewritten positions, resync. */
  protected async drop(event: CdkDragDrop<DailyPlanEntry[]>): Promise<void> {
    if (event.previousIndex === event.currentIndex || this.busy()) {
      return;
    }
    const next = [...this.planned()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.planned.set(next); // optimistic preview
    await this.commit(writeItemsFrom(next), 'Order saved', () =>
      this.planned.set(plannedEntries(this.plan()?.items ?? [])),
    );
  }

  /** Add an un-planned todo to today's plan. */
  protected async add(todo: TodoRow): Promise<void> {
    if (this.busy()) {
      return;
    }
    this._picking.set(false);
    await this.commit(
      appendWriteItems(this.planned(), todo.id),
      'Added to today',
    );
  }

  /** Remove a planned item. Disabled when it would empty the plan. */
  protected async remove(todoId: string): Promise<void> {
    if (this.busy() || this.isLastPlanned(todoId)) {
      return;
    }
    await this.commit(
      removeWriteItems(this.planned(), todoId),
      'Removed from today',
    );
  }

  /**
   * Run one atomic PUT and re-render from the server envelope. `onError`
   * rolls back any optimistic local state; it defaults to a no-op for
   * writes (add/remove) whose state derives entirely from the resource.
   */
  private async commit(
    items: ReturnType<typeof writeItemsFrom>,
    successMessage: string,
    onError: () => void = () => undefined,
  ): Promise<void> {
    this._busy.set(true);
    try {
      const result = await firstValueFrom(this.dailyPlanService.replace(items));
      // Re-seed the resource so plan(), planned(), and candidates() all
      // recompute from the authoritative new plan.
      this.planResource.set({
        date: result.date,
        items: result.items,
        total: result.total,
        done: result.items.filter((i) => i.state === 'done').length,
        overdue_count: 0,
      });
      // candidates() recomputes from the re-seeded plan: an added todo drops
      // out of the picker because it's now in plan.items, a removed one
      // re-appears. The todo rows themselves are unchanged (planning doesn't
      // mutate todo state), so the source list needs no refetch.
      this.notifications.success(successMessage);
    } catch {
      onError();
      this.notifications.error('Could not save the plan — try again');
    } finally {
      this._busy.set(false);
    }
  }
}
