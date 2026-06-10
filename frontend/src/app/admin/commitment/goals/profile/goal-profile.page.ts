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
import { map, type Observable } from 'rxjs';
import { PlanService } from '../../../../core/services/plan.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { GoalDetail, Milestone } from '../../../../core/models/admin.model';
import type { GoalStatus } from '../../../../core/models';
import {
  GOAL_STATUS_CHIP_CLASS,
  GOAL_STATUS_DOT_CLASS,
  GOAL_STATUS_LABEL,
  GOAL_STATUS_OPTIONS,
} from '../goal-status';

/**
 * Goal detail — title/description with a status chip + change menu,
 * meta strip, milestones (inline add + click-to-toggle), linked
 * projects, and the recent-activity rail. The status endpoint returns
 * a partial object, so every mutation re-fetches the detail.
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

  protected readonly statusOptions = GOAL_STATUS_OPTIONS;

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
  protected readonly newMilestoneTitle = signal('');

  protected readonly milestonesDone = computed(
    () => this.goal()?.milestones.filter((m) => !!m.completed_at).length ?? 0,
  );

  constructor() {
    this.topbar.set({ title: 'Goal', crumbs: ['Commitment', 'Goals'] });

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

  protected statusChipClass(status: GoalStatus): string {
    return GOAL_STATUS_CHIP_CLASS[status];
  }

  protected statusDotClass(status: GoalStatus): string {
    return GOAL_STATUS_DOT_CLASS[status];
  }

  protected statusLabel(status: GoalStatus): string {
    return GOAL_STATUS_LABEL[status];
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
    this.closeStatusMenu();
    if (!g || this._isActioning() || status === g.status) return;

    this.mutate(this.planService.updateGoalStatus(g.id, status), {
      success: `Status → ${GOAL_STATUS_LABEL[status]}`,
      badRequest: 'Illegal status transition.',
      failure: 'Failed to update status.',
    });
  }

  protected onMilestoneInput(event: Event): void {
    this.newMilestoneTitle.set((event.target as HTMLInputElement).value);
  }

  protected addMilestone(): void {
    const g = this.goal();
    const title = this.newMilestoneTitle().trim();
    if (!g || !title || this._isActioning()) return;

    this.mutate(this.planService.createMilestone(g.id, title), {
      success: 'Milestone added',
      conflict: 'A milestone with that title already exists.',
      failure: 'Failed to add milestone.',
      onSuccess: () => this.newMilestoneTitle.set(''),
    });
  }

  protected toggleMilestone(m: Milestone): void {
    const g = this.goal();
    if (!g || this._isActioning()) return;

    this.mutate(this.planService.toggleMilestone(g.id, m.id), {
      failure: 'Failed to update milestone.',
    });
  }

  /** Runs a mutation, toasts the outcome, and re-fetches the detail. */
  private mutate<T>(
    request: Observable<T>,
    msg: {
      success?: string;
      conflict?: string;
      badRequest?: string;
      failure: string;
      onSuccess?: () => void;
    },
  ): void {
    this._isActioning.set(true);
    request.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this._isActioning.set(false);
        msg.onSuccess?.();
        if (msg.success) this.notifications.success(msg.success);
        this.resource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        if (status === 409 && msg.conflict) {
          this.notifications.error(msg.conflict);
        } else if (status === 400 && msg.badRequest) {
          this.notifications.error(msg.badRequest);
        } else {
          this.notifications.error(msg.failure);
        }
      },
    });
  }
}

function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}
