import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import {
  rxResource,
  takeUntilDestroyed,
  toSignal,
} from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import { PlanService } from '../../../../core/services/plan.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { GoalDetail } from '../../../../core/models/admin.model';
import type { GoalStatus } from '../../../../core/models';

const STATUS_DOT_CLASS: Record<GoalStatus, string> = {
  not_started: 'bg-zinc-400',
  in_progress: 'bg-sky-400',
  on_hold: 'bg-amber-400',
  done: 'bg-emerald-500',
  abandoned: 'bg-zinc-600',
};

const STATUS_LABEL: Record<GoalStatus, string> = {
  not_started: 'not started',
  in_progress: 'in progress',
  on_hold: 'on hold',
  done: 'done',
  abandoned: 'abandoned',
};

// All 5 statuses are surfaced; legal transitions are enforced
// server-side. Illegal transitions come back as HTTP 400 and are
// toasted as "Illegal state transition".
const STATUS_OPTIONS: readonly GoalStatus[] = [
  'not_started',
  'in_progress',
  'on_hold',
  'done',
  'abandoned',
];

const HEALTH_LABEL: Record<NonNullable<GoalDetail['health']>, string> = {
  'on-track': 'on track',
  'at-risk': 'at risk',
  stalled: 'stalled',
};

const HEALTH_CLASS: Record<NonNullable<GoalDetail['health']>, string> = {
  'on-track': 'text-emerald-300',
  'at-risk': 'text-amber-300',
  stalled: 'text-red-300',
};

/**
 * Goal Profile Hero header + Overview +
 * Milestones (binary checklist, no percent-complete) + linked Projects
 * + Activity + System. Status changes go through
 */
@Component({
  selector: 'app-goal-profile-page',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './goal-profile.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class GoalProfilePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly planService = inject(PlanService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusOptions = STATUS_OPTIONS;

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<GoalDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.planService.getGoalDetail(params),
  });

  protected readonly goal = computed(() => this.resource.value());
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.goal(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  protected readonly isStatusMenuOpen = signal(false);

  /**
   * Aggregate count derived client-side. Milestones themselves are
   * binary (completed/not) —
   * this value is a headline signal over the set, NOT per-milestone
   * percent-complete which the contract forbids.
   */
  protected readonly milestonePercent = computed(() => {
    const g = this.goal();
    if (!g || g.milestones.length === 0) return 0;
    const done = g.milestones.filter((m) => m.completed).length;
    return Math.round((done / g.milestones.length) * 100);
  });

  constructor() {
    this.topbar.set({
      title: 'Goal',
      crumbs: ['Commitment', 'Goals & projects'],
    });

    effect(() => {
      const g = this.goal();
      if (!g) return;
      this.topbar.set({
        title: `Goal · ${truncate(g.title, 40)}`,
        crumbs: ['Commitment', 'Goals', g.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected statusDotClass(status: GoalStatus): string {
    return STATUS_DOT_CLASS[status];
  }

  protected statusLabel(status: GoalStatus): string {
    return STATUS_LABEL[status];
  }

  protected healthLabel(health: GoalDetail['health']): string {
    return HEALTH_LABEL[health];
  }

  protected healthClass(health: GoalDetail['health']): string {
    return HEALTH_CLASS[health];
  }

  protected back(): void {
    this.router.navigate(['/admin/commitment/goals']);
  }

  protected openProject(projectId: string): void {
    this.router.navigate(['/admin/commitment/projects', projectId]);
  }

  protected toggleStatusMenu(): void {
    this.isStatusMenuOpen.update((v) => !v);
  }

  protected closeStatusMenu(): void {
    this.isStatusMenuOpen.set(false);
  }

  protected updateStatus(status: GoalStatus): void {
    const g = this.goal();
    if (!g || this._isActioning() || status === g.status) {
      this.closeStatusMenu();
      return;
    }

    this._isActioning.set(true);
    this.closeStatusMenu();
    this.planService
      .updateGoalStatus(g.id, status)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(`Status set to ${STATUS_LABEL[status]}.`);
          this.resource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          const httpStatus =
            err instanceof HttpErrorResponse ? err.status : null;
          if (httpStatus === 400) {
            this.notifications.error('Illegal status transition.');
          } else {
            this.notifications.error('Failed to update status.');
          }
        },
      });
  }
}

function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}
