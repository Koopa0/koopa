import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { Repeat, LucideAngularModule } from 'lucide-angular';
import {
  TodoService,
  type RecurringBuckets,
  type TodoItem,
} from '../../../core/services/todo.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';
import { EnergyMeterComponent } from '../../../shared/components/energy-meter/energy-meter.component';
import { energyOf, recurLabel } from '../todos/gtd-view';
import type { EnergyLevel } from '../../../core/models/workbench.model';

/**
 * Routines — the overview of every active recurring schedule, not just the ones
 * due today. It is the home for the routine-as-a-whole that the Today dashboard
 * (which only shows what is due today) and the Todos status tabs (which exclude
 * routines) deliberately do not surface. Read-only: a routine's schedule is
 * edited from its detail panel on the Todos page; today's occurrence is
 * completed on the Today dashboard. This view answers "what routines do I keep,
 * and when did each last run".
 */
@Component({
  selector: 'app-routines-page',
  imports: [
    DatePipe,
    LucideAngularModule,
    EmptyStateComponent,
    EnergyMeterComponent,
  ],
  templateUrl: './routines.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class RoutinesPageComponent {
  private readonly todoService = inject(TodoService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly RepeatIcon = Repeat;

  private readonly resource = rxResource<RecurringBuckets, void>({
    stream: () => this.todoService.recurring(),
  });

  // Guard the read: rxResource.value() throws in the error state, so gate on
  // hasValue() (the repo idiom) — a failed load shows the error UI, not a throw.
  private readonly buckets = computed(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.buckets(),
  );
  protected readonly isError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly routines = computed(() => this.buckets()?.all ?? []);

  /** Ids due today, so each routine can show a "due today" marker. */
  private readonly dueTodayIds = computed(
    () => new Set((this.buckets()?.due_today ?? []).map((t) => t.id)),
  );

  constructor() {
    this.topbar.set({ title: 'Routines', crumbs: ['Daily', 'Routines'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected retry(): void {
    this.resource.reload();
  }

  protected scheduleLabel(routine: TodoItem): string {
    return (
      recurLabel(
        routine.recur_interval,
        routine.recur_unit,
        routine.recur_weekdays,
      ) ?? 'recurring'
    );
  }

  protected energyLevel(routine: TodoItem): EnergyLevel | null {
    return energyOf(routine.energy);
  }

  protected isDueToday(routine: TodoItem): boolean {
    return this.dueTodayIds().has(routine.id);
  }
}
