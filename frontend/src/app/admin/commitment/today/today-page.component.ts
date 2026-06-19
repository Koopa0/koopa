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
import { Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { switchMap } from 'rxjs';
import { Hexagon, LucideAngularModule } from 'lucide-angular';
import {
  TodayService,
  type CommittedItem,
  type PendingDetail,
  type TodayBrief,
} from './today.service';
import {
  GOAL_VARIANT,
  applyPlanAdvance,
  buildLooseGroups,
  computeFigures,
  energyOf,
  greetingForHour,
  isQuietBrief,
  planAdvanceAction,
  removeLooseTodo,
  truncateTitle,
} from './today-view';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { CommandPaletteService } from '../../../shared/command-palette/command-palette.service';
import { NotificationService } from '../../../core/services/notification.service';
import { ProposalService } from '../../../core/services/proposal.service';
import { TodoService } from '../../../core/services/todo.service';
import { EnergyMeterComponent } from '../../../shared/components/energy-meter/energy-meter.component';
import {
  StatusBadgeComponent,
  type BadgeVariant,
} from '../../../shared/components/status-badge/status-badge.component';
import type { GoalStatus } from '../../../core/models/api.model';
import type { EnergyLevel } from '../../../core/models/workbench.model';

/**
 * Today — the Daily landing page, bound to the brief(morning) aggregate
 * (GET /api/admin/commitment/today). Day header with capture bar, live
 * plan-completion strip, the committed plan with advance-on-click, loose
 * todos grouped overdue/today/upcoming, and the right rail: active goals
 * and RSS highlights. Lists are always [] on the wire; advances mutate a
 * local working copy after the server confirms.
 */
@Component({
  selector: 'app-today-page',
  imports: [
    RouterLink,
    DatePipe,
    LucideAngularModule,
    EnergyMeterComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './today-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class TodayPageComponent {
  private readonly todayService = inject(TodayService);
  private readonly todoService = inject(TodoService);
  private readonly proposalService = inject(ProposalService);
  private readonly notifications = inject(NotificationService);
  private readonly palette = inject(CommandPaletteService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly HexagonIcon = Hexagon;
  protected readonly greeting = signal(greetingForHour(new Date().getHours()));

  protected readonly resource = rxResource<TodayBrief, void>({
    stream: () => this.todayService.today(),
  });

  // Local working copy of the brief; advance interactions update it. Guard the
  // read: rxResource.value() throws while the resource is in an error state, so
  // gate on hasValue() (the repo idiom). isError() drives the error UI;
  // without this guard a failed fetch throws here and the error UI is dead.
  protected readonly brief = linkedSignal(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.brief(),
  );
  protected readonly isError = computed(
    () => this.resource.status() === 'error',
  );

  // Proposals-awaiting-review pointer. A standalone, fail-safe read: a broken
  // count just hides the pointer (guard the read — value() throws in error
  // state). The proposed rows themselves are NEVER pulled into Today; this is
  // a count + link only, the inert drafts live solely on the triage page.
  private readonly proposalsCount = rxResource<number, void>({
    stream: () => this.proposalService.count(),
  });
  protected readonly proposalsPending = computed(() =>
    this.proposalsCount.hasValue() ? this.proposalsCount.value() : 0,
  );

  private readonly _busy = signal(false);
  protected readonly busy = this._busy.asReadonly();

  protected readonly figures = computed(() => computeFigures(this.brief()));

  protected readonly looseGroups = computed(() =>
    buildLooseGroups(this.brief()),
  );

  protected readonly isQuiet = computed(() => {
    const v = this.brief();
    return v ? isQuietBrief(v) : false;
  });

  constructor() {
    this.topbar.set({
      title: 'Today',
      crumbs: ['Daily', 'Today'],
      actions: [
        {
          id: 'today-open-plan',
          label: 'Plan',
          kind: 'secondary',
          run: () => void this.router.navigate(['/admin/daily/plan']),
        },
      ],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected openPalette(): void {
    this.palette.open();
  }

  protected retry(): void {
    this.resource.reload();
  }

  protected goalPercent(done: number, total: number): number {
    if (total <= 0) return 0;
    return Math.round((done / total) * 100);
  }

  protected goalVariant(status: GoalStatus): BadgeVariant {
    return GOAL_VARIANT[status];
  }

  protected statusLabel(status: string): string {
    return status.replaceAll('_', ' ');
  }

  protected energyLevel(value?: string | null): EnergyLevel | null {
    return energyOf(value);
  }

  /** todo → in_progress → done, one server-confirmed step per click. */
  protected advancePlan(item: CommittedItem): void {
    const action = planAdvanceAction(item);
    if (!action || this._busy()) return;
    this._busy.set(true);
    this.todoService.advance(item.todo_id, action).subscribe({
      next: () => {
        this._busy.set(false);
        this.brief.update((v) => (v ? applyPlanAdvance(v, item.id, action) : v));
        if (action === 'complete') {
          this.notifications.success(
            `Marked done · ${truncateTitle(item.todo_title)}`,
          );
        }
      },
      error: () => {
        this._busy.set(false);
        this.notifications.error('Could not advance the todo.');
      },
    });
  }

  /** One-click complete; not-yet-started todos pass through start first. */
  protected completeLoose(todo: PendingDetail): void {
    if (this._busy()) return;
    this._busy.set(true);
    const complete$ =
      todo.state === 'in_progress'
        ? this.todoService.advance(todo.id, 'complete')
        : this.todoService
            .advance(todo.id, 'start')
            .pipe(
              switchMap(() => this.todoService.advance(todo.id, 'complete')),
            );
    complete$.subscribe({
      next: () => {
        this._busy.set(false);
        this.brief.update((v) => (v ? removeLooseTodo(v, todo.id) : v));
        this.notifications.success('Completed');
      },
      error: () => {
        this._busy.set(false);
        this.notifications.error('Could not complete the todo.');
      },
    });
  }
}
