import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { form, FormField, required, maxLength } from '@angular/forms/signals';
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface GoalForm {
  title: string;
  description: string;
  quarter: string;
  deadline: string;
}

/** Quarter options `YYYY-Qn` for the current and next year (8 options). */
function quarterOptions(currentYear: number): string[] {
  const out: string[] = [];
  for (const year of [currentYear, currentYear + 1]) {
    for (const q of [1, 2, 3, 4]) {
      out.push(`${year}-Q${q}`);
    }
  }
  return out;
}

/**
 * Goal create — a Signal Forms reactive form. Title is required and capped at
 * 200 chars (server contract); description, quarter, and deadline are optional.
 * Status is server-set (`not_started`) and not part of creation. The admin UI
 * owns commitment creation: this form is the only path to a new goal.
 */
@Component({
  selector: 'app-goal-create-page',
  standalone: true,
  imports: [RouterLink, FormField],
  templateUrl: './goal-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class GoalCreatePageComponent {
  private readonly planService = inject(PlanService);
  private readonly router = inject(Router);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly quarters = quarterOptions(new Date().getFullYear());
  protected readonly submitting = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly model = signal<GoalForm>({
    title: '',
    description: '',
    quarter: '',
    deadline: '',
  });

  protected readonly goalForm = form(this.model, (path) => {
    required(path.title, { message: 'Title is required' });
    maxLength(path.title, 200, {
      message: 'Title must be 200 characters or fewer',
    });
  });

  constructor() {
    this.topbar.set({ title: 'New goal', crumbs: ['Commitment', 'Goals', 'New'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected save(): void {
    if (this.goalForm().invalid() || this.submitting()) return;

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    this.planService
      .createGoal({
        title: v.title.trim(),
        description: v.description.trim(),
        quarter: v.quarter || undefined,
        // Date input yields YYYY-MM-DD; pin to UTC midnight for an RFC3339 value.
        deadline: v.deadline ? `${v.deadline}T00:00:00Z` : undefined,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (goal) =>
          this.router.navigate(['/admin/commitment/goals', goal.id]),
        error: () => {
          this.submitting.set(false);
          this.serverError.set(
            'Could not create the goal. Check the fields and try again.',
          );
        },
      });
  }
}
