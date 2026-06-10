import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import {
  form,
  FormField,
  required,
  maxLength,
  validate,
  minLengthError,
} from '@angular/forms/signals';
import { PlanService } from '../../../../core/services/plan.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface GoalForm {
  title: string;
  description: string;
  quarter: string;
  deadline: string;
}

const TITLE_MAX = 90;
const TITLE_MIN = 6;
const TITLE_TOO_SHORT = 'Give it at least 6 characters — a real commitment.';

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

/**
 * Goal create — Signal Forms. Title is required (trimmed length >= 6,
 * max 90); description, quarter, and deadline are optional. Status is
 * server-set (`not_started`) and never part of the form. Field errors
 * show after blur or a submit attempt; an invalid submit raises the
 * banner and a toast, and disables the create button until valid.
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
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly titleMax = TITLE_MAX;
  protected readonly quarters = quarterOptions(new Date());
  protected readonly submitting = signal(false);
  protected readonly submitted = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly model = signal<GoalForm>({
    title: '',
    description: '',
    quarter: '',
    deadline: '',
  });

  protected readonly goalForm = form(this.model, (path) => {
    required(path.title, { message: TITLE_TOO_SHORT });
    validate(path.title, ({ value }) => {
      const trimmed = value().trim();
      return trimmed.length > 0 && trimmed.length < TITLE_MIN
        ? minLengthError(TITLE_MIN, { message: TITLE_TOO_SHORT })
        : undefined;
    });
    maxLength(path.title, TITLE_MAX, {
      message: `Keep it under ${TITLE_MAX} characters.`,
    });
  });

  constructor() {
    this.topbar.set({ title: 'New goal', crumbs: ['Commitment', 'Goals', 'New'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  /** Field errors show after blur (touched) or any submit attempt. */
  protected showErrors(field: {
    touched(): boolean;
    invalid(): boolean;
  }): boolean {
    return (field.touched() || this.submitted()) && field.invalid();
  }

  protected save(): void {
    if (this.submitting()) return;

    if (this.goalForm().invalid()) {
      this.submitted.set(true);
      this.notifications.error('Fix the highlighted fields');
      return;
    }

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
        next: (goal) => {
          this.notifications.success('Goal created · status set to not_started');
          this.router.navigate(['/admin/commitment/goals', goal.id]);
        },
        error: () => {
          this.submitting.set(false);
          this.serverError.set(
            'Could not create the goal. Check the fields and try again.',
          );
        },
      });
  }
}
