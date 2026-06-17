import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { form, FormField, required, maxLength } from '@angular/forms/signals';
import { LearningService } from '../../../../core/services/learning.service';
import type { Domain } from '../../../../core/services/learning.service';
import { PlanService } from '../../../../core/services/plan.service';
import type { GoalsOverview } from '../../../../core/models/admin.model';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface PlanForm {
  title: string;
  description: string;
  domain: string;
  goal_id: string;
}

const TITLE_MAX = 80;
const TARGET_COUNT_MIN = 3;
const TARGET_COUNT_MAX = 20;
const TARGET_COUNT_DEFAULT = 9;
const GOAL_LABEL_MAX = 40;

/**
 * Plan create — a Signal Forms reactive form. Title and domain are required;
 * description and goal link are optional. The domain select is fed by
 * `getDomains()`: when no domains exist the form degrades to an inline notice
 * and stays unsubmittable (domain is required). The goal select is optional
 * and sourced from the commitment goals overview.
 *
 * Validation gating follows the design's Signal Forms pattern: per-field
 * errors surface after blur (touched) OR after a submit attempt; an invalid
 * submit raises the form banner and only then disables the submit button
 * while the form stays invalid. The server always creates `status=draft`.
 *
 * Target count is a range slider (3–20, default 9) managed outside the form
 * schema because Signal Forms rejects native constraint attributes
 * (min/max) on `[formField]` nodes.
 */
@Component({
  selector: 'app-plan-create-page',
  imports: [RouterLink, FormField],
  templateUrl: './plan-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class PlanCreatePageComponent {
  private readonly learningService = inject(LearningService);
  private readonly planService = inject(PlanService);
  private readonly router = inject(Router);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly submitting = signal(false);
  protected readonly submitted = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly targetCountMin = TARGET_COUNT_MIN;
  protected readonly targetCountMax = TARGET_COUNT_MAX;
  protected readonly targetCount = signal(TARGET_COUNT_DEFAULT);

  protected readonly titleMax = TITLE_MAX;

  protected readonly domainsResource = rxResource<Domain[], void>({
    stream: () => this.learningService.getDomains(),
  });
  protected readonly domains = computed(
    () => this.domainsResource.value() ?? [],
  );
  protected readonly hasDomains = computed(() => this.domains().length > 0);

  protected readonly goalsResource = rxResource<GoalsOverview, void>({
    stream: () => this.planService.getGoalsOverview(),
  });
  protected readonly goals = computed(
    () => this.goalsResource.value()?.goals ?? [],
  );

  protected readonly model = signal<PlanForm>({
    title: '',
    description: '',
    domain: '',
    goal_id: '',
  });

  protected readonly planForm = form(this.model, (path) => {
    required(path.title, { message: 'Title is required.' });
    maxLength(path.title, TITLE_MAX, {
      message: `Title must be ${TITLE_MAX} characters or fewer.`,
    });
    required(path.domain, { message: 'A plan must belong to a domain.' });
  });

  protected readonly titleCount = computed(() => this.model().title.length);

  /** Banner + disabled-submit only engage after the first submit attempt. */
  protected readonly showInvalidBanner = computed(
    () => this.submitted() && this.planForm().invalid(),
  );

  constructor() {
    this.topbar.set({ title: 'New plan', crumbs: ['Learning', 'Plans', 'New'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected goalLabel(title: string): string {
    return title.length > GOAL_LABEL_MAX
      ? `${title.slice(0, GOAL_LABEL_MAX)}…`
      : title;
  }

  protected setTargetCount(event: Event): void {
    const raw = Number((event.target as HTMLInputElement).value);
    const clamped = Math.min(
      TARGET_COUNT_MAX,
      Math.max(TARGET_COUNT_MIN, Math.round(raw)),
    );
    this.targetCount.set(clamped);
  }

  protected save(): void {
    if (this.submitting()) return;
    if (this.planForm().invalid()) {
      this.submitted.set(true);
      return;
    }

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    this.learningService
      .createPlan({
        title: v.title.trim(),
        description: v.description.trim(),
        domain: v.domain,
        goal_id: v.goal_id || undefined,
        target_count: this.targetCount(),
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (created) =>
          this.router.navigate(['/admin/learning/plans', created.id]),
        error: () => {
          this.submitting.set(false);
          this.serverError.set(
            'Could not create the plan. Check the fields and try again.',
          );
        },
      });
  }
}
