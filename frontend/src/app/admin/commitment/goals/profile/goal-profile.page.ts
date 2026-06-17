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
import {
  form,
  FormField,
  required,
  maxLength,
} from '@angular/forms/signals';
import {
  PlanService,
  type Area,
  type GoalUpdateRequest,
} from '../../../../core/services/plan.service';
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

const TITLE_MAX = 90;

/** Editable shaping fields for the goal edit form. */
interface GoalEditForm {
  title: string;
  description: string;
  area_id: string;
  quarter: string;
  deadline: string;
}

/**
 * Goal detail — title/description with a status chip + change menu,
 * meta strip, milestones (inline add + click-to-toggle), linked
 * projects, and the recent-activity rail. The status endpoint returns
 * a partial object, so every mutation re-fetches the detail.
 */
@Component({
  selector: 'app-goal-profile-page',
  imports: [DatePipe, FormField],
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
  protected readonly titleMax = TITLE_MAX;

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

  // --- Goal edit ---

  // PARA areas for the edit form's area selector. An empty / failed read
  // just leaves the select with its "no area" placeholder.
  private readonly areasResource = rxResource<Area[], void>({
    stream: () => this.planService.getAreas(),
  });
  protected readonly areas = computed<Area[]>(() =>
    this.areasResource.hasValue() ? this.areasResource.value() : [],
  );

  // Current quarter plus the next three, with the goal's own quarter folded
  // in so an out-of-window value still renders as the selected option.
  protected readonly quarters = computed<string[]>(() => {
    const base = quarterOptions(new Date());
    const current = this.goal()?.quarter;
    return current && !base.includes(current) ? [current, ...base] : base;
  });
  protected readonly isEditing = signal(false);

  protected readonly editModel = signal<GoalEditForm>({
    title: '',
    description: '',
    area_id: '',
    quarter: '',
    deadline: '',
  });

  protected readonly editForm = form(this.editModel, (path) => {
    required(path.title, { message: 'Title is required.' });
    maxLength(path.title, TITLE_MAX, {
      message: `Keep it under ${TITLE_MAX} characters.`,
    });
  });

  // --- Milestone inline edit / delete ---

  // The milestone awaiting a delete confirm (one at a time), and the
  // milestone whose title is being edited inline.
  protected readonly confirmingDeleteId = signal<string | null>(null);
  protected readonly editingMilestoneId = signal<string | null>(null);
  protected readonly editingMilestoneTitle = signal('');

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

  // --- Goal edit ---

  /** Enter edit mode, seeding the form from the loaded goal. */
  protected startEdit(): void {
    const g = this.goal();
    if (!g) return;
    this.editModel.set({
      title: g.title,
      description: g.description,
      area_id: g.area_id ?? '',
      quarter: g.quarter ?? '',
      // deadline arrives as YYYY-MM-DD from the detail; the date input wants
      // exactly that.
      deadline: g.deadline ?? '',
    });
    this.isEditing.set(true);
  }

  protected cancelEdit(): void {
    this.isEditing.set(false);
  }

  /**
   * Persist the goal's shaping fields. Only fields that changed from the
   * loaded goal are sent — the backend update is partial and omitted
   * fields stay unchanged. Status is never part of this form.
   */
  protected saveEdit(): void {
    const g = this.goal();
    if (!g || this._isActioning()) return;
    if (this.editForm().invalid()) {
      this.notifications.error('Fix the highlighted fields');
      return;
    }

    const v = this.editModel();
    const body: GoalUpdateRequest = {};
    const title = v.title.trim();
    if (title !== g.title) body.title = title;
    if (v.description.trim() !== g.description)
      body.description = v.description.trim();
    if (v.quarter !== (g.quarter ?? '')) body.quarter = v.quarter;
    if (v.area_id !== (g.area_id ?? '')) body.area_id = v.area_id;
    if (v.deadline !== (g.deadline ?? ''))
      body.deadline = v.deadline ? `${v.deadline}T00:00:00Z` : '';

    this.mutate(this.planService.updateGoal(g.id, body), {
      success: 'Goal updated',
      failure: 'Failed to update the goal.',
      onSuccess: () => this.isEditing.set(false),
    });
  }

  protected onEditAreaChange(event: Event): void {
    this.editModel.update((m) => ({
      ...m,
      area_id: (event.target as HTMLSelectElement).value,
    }));
  }

  protected onEditQuarterChange(event: Event): void {
    this.editModel.update((m) => ({
      ...m,
      quarter: (event.target as HTMLSelectElement).value,
    }));
  }

  protected onEditDeadlineChange(event: Event): void {
    this.editModel.update((m) => ({
      ...m,
      deadline: (event.target as HTMLInputElement).value,
    }));
  }

  // --- Milestone delete (two-step inline confirm) ---

  protected requestDeleteMilestone(m: Milestone): void {
    this.confirmingDeleteId.set(m.id);
  }

  protected cancelDeleteMilestone(): void {
    this.confirmingDeleteId.set(null);
  }

  protected confirmDeleteMilestone(m: Milestone): void {
    const g = this.goal();
    this.confirmingDeleteId.set(null);
    if (!g || this._isActioning()) return;

    this.mutate(this.planService.deleteMilestone(g.id, m.id), {
      success: 'Milestone deleted',
      failure: 'Failed to delete milestone.',
    });
  }

  // --- Milestone inline title edit ---

  protected startMilestoneEdit(m: Milestone): void {
    this.editingMilestoneId.set(m.id);
    this.editingMilestoneTitle.set(m.title);
  }

  protected onMilestoneEditInput(event: Event): void {
    this.editingMilestoneTitle.set((event.target as HTMLInputElement).value);
  }

  protected cancelMilestoneEdit(): void {
    this.editingMilestoneId.set(null);
  }

  protected saveMilestoneEdit(m: Milestone): void {
    const g = this.goal();
    const title = this.editingMilestoneTitle().trim();
    if (!g || this._isActioning()) return;
    if (!title || title === m.title) {
      this.editingMilestoneId.set(null);
      return;
    }

    this.mutate(this.planService.updateMilestone(g.id, m.id, { title }), {
      success: 'Milestone updated',
      conflict: 'A milestone with that title already exists.',
      failure: 'Failed to update milestone.',
      onSuccess: () => this.editingMilestoneId.set(null),
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

/** Quarter options `YYYY-Qn` — the current quarter plus the next three. */
function quarterOptions(now: Date): string[] {
  const out: string[] = [];
  let year = now.getFullYear();
  let quarter = Math.floor(now.getMonth() / 3) + 1;
  for (let i = 0; i < 4; i++) {
    out.push(`${year}-Q${quarter}`);
    quarter++;
    if (quarter > 4) {
      quarter = 1;
      year++;
    }
  }
  return out;
}
