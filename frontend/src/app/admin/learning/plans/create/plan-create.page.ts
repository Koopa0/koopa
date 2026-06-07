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
  target_count: number;
}

/**
 * Plan create — a Signal Forms reactive form. Title and domain are required;
 * description, goal link, and target count are optional. The domain select is
 * fed by `getDomains()`: when no domains exist the form degrades to an inline
 * notice and stays unsubmittable (domain is required). The goal select is
 * optional and sourced from the commitment goals overview. Target count is a
 * plain number input; its lower bound is enforced in {@link save} (only sent
 * when > 0) because Signal Forms rejects the native `min` constraint attribute
 * on `[formField]` nodes.
 */
@Component({
  selector: 'app-plan-create-page',
  standalone: true,
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
  protected readonly serverError = signal<string | null>(null);

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
    target_count: 0,
  });

  protected readonly planForm = form(this.model, (path) => {
    required(path.title, { message: 'Title is required' });
    maxLength(path.title, 200, {
      message: 'Title must be 200 characters or fewer',
    });
    required(path.domain, { message: 'A domain is required' });
  });

  constructor() {
    this.topbar.set({ title: 'New plan', crumbs: ['Learning', 'Plans', 'New'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected save(): void {
    if (this.planForm().invalid() || this.submitting()) return;

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    this.learningService
      .createPlan({
        title: v.title.trim(),
        description: v.description.trim(),
        domain: v.domain,
        goal_id: v.goal_id || undefined,
        target_count: v.target_count > 0 ? v.target_count : undefined,
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
