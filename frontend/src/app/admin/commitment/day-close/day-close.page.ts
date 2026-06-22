import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  linkedSignal,
  signal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { CalendarCheck, LucideAngularModule, Moon } from 'lucide-angular';

import { EmptyStateComponent } from '../../../shared/components';
import { NotificationService } from '../../../core/services/notification.service';
import { TodoService } from '../../../core/services/todo.service';
import { DailyPlanService } from '../../../core/services/daily-plan.service';
import { DayCloseService } from './day-close.service';
import {
  appendTodoToToday,
  removeResolvedItem,
  totalUnresolved,
  type UnclosedDay,
} from './day-close-view';

/**
 * Day close — the evening confrontation. Loads every unclosed day in the
 * lookback window (not just yesterday: skipped/forgotten closes pile up
 * and are all surfaced) and confronts each unresolved planned item with
 * three choices: re-plan to today, drop, or leave. Re-plan and drop
 * persist via the existing daily-plan PUT and todo-advance endpoints, so
 * the item leaves the confrontation; "leave" is a deliberate no-op — the
 * item reappears next time, which is the no-auto-carryover feature.
 *
 * Nothing here records a "last close" marker; resolved items drop out
 * naturally on the next read.
 */
@Component({
  selector: 'app-day-close-page',
  imports: [DatePipe, LucideAngularModule, EmptyStateComponent],
  templateUrl: './day-close.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DayClosePageComponent {
  private readonly dayCloseService = inject(DayCloseService);
  private readonly todoService = inject(TodoService);
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly notifications = inject(NotificationService);

  protected readonly MoonIcon = Moon;
  protected readonly CalendarCheckIcon = CalendarCheck;

  private readonly resource = rxResource<UnclosedDay[], void>({
    stream: () => this.dayCloseService.unclosedDays(),
  });

  /** Local working copy; per-item actions splice resolved items out of it. */
  protected readonly days = linkedSignal<UnclosedDay[]>(
    () => this.resource.value() ?? [],
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.resource.hasValue(),
  );
  protected readonly isError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly totalUnresolved = computed(() =>
    totalUnresolved(this.days()),
  );
  protected readonly isClear = computed(
    () => !this.isLoading() && !this.isError() && this.days().length === 0,
  );

  private readonly _busy = signal(false);
  protected readonly busy = this._busy.asReadonly();

  protected retry(): void {
    this.resource.reload();
  }

  /** Re-plan an item to today: append it to today's plan, then drop from the confrontation. */
  protected async replanToToday(date: string, todoId: string): Promise<void> {
    if (this.busy()) {
      return;
    }
    this._busy.set(true);
    try {
      const todayPlan = await firstValueFrom(this.dailyPlanService.today());
      const items = appendTodoToToday(todayPlan.items, todoId);
      await firstValueFrom(this.dailyPlanService.replace(items));
      this.days.set(removeResolvedItem(this.days(), date, todoId));
      this.notifications.success('Re-planned to today');
    } catch {
      this.notifications.error('Could not re-plan — try again');
    } finally {
      this._busy.set(false);
    }
  }

  /** Drop an item: advance the backing todo to dropped, then remove from the confrontation. */
  protected async drop(date: string, todoId: string): Promise<void> {
    if (this.busy()) {
      return;
    }
    this._busy.set(true);
    try {
      await firstValueFrom(this.todoService.advance(todoId, 'drop'));
      this.days.set(removeResolvedItem(this.days(), date, todoId));
      this.notifications.info('Dropped');
    } catch {
      this.notifications.error('Could not drop — try again');
    } finally {
      this._busy.set(false);
    }
  }

  /**
   * Leave an item visible: a deliberate no-op. The item is NOT removed
   * from state — it stays in this confrontation and reappears next time.
   * That reappearance is the no-auto-carryover feature; "leave" exists so
   * the choice is conscious rather than implicit.
   */
  protected leave(): void {
    this.notifications.info('Left for next time');
  }
}
