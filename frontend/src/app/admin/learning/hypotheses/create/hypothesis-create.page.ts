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
import { HypothesisService } from '../../../../core/services/hypothesis.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface HypothesisForm {
  claim: string;
  invalidation_condition: string;
  content: string;
  observed_date: string;
}

/**
 * Hypothesis create — a falsifiable claim plus the condition that would
 * invalidate it (both required). Lands `state=unverified`; verify/invalidate
 * happen later from the profile. Signal Forms, mirroring the Goal create form.
 */
@Component({
  selector: 'app-hypothesis-create-page',
  standalone: true,
  imports: [RouterLink, FormField],
  templateUrl: './hypothesis-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class HypothesisCreatePageComponent {
  private readonly hypothesisService = inject(HypothesisService);
  private readonly router = inject(Router);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly submitting = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly model = signal<HypothesisForm>({
    claim: '',
    invalidation_condition: '',
    content: '',
    observed_date: '',
  });

  protected readonly hypForm = form(this.model, (path) => {
    required(path.claim, { message: 'A claim is required' });
    maxLength(path.claim, 1000, {
      message: 'Claim must be 1000 characters or fewer',
    });
    required(path.invalidation_condition, {
      message: 'An invalidation condition is required',
    });
  });

  constructor() {
    this.topbar.set({
      title: 'New hypothesis',
      crumbs: ['Learning', 'Hypotheses', 'New'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected save(): void {
    if (this.hypForm().invalid() || this.submitting()) return;

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    this.hypothesisService
      .create({
        claim: v.claim.trim(),
        invalidation_condition: v.invalidation_condition.trim(),
        content: v.content.trim() || undefined,
        observed_date: v.observed_date || undefined,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (hyp) =>
          this.router.navigate(['/admin/learning/hypotheses', hyp.id]),
        error: () => {
          this.submitting.set(false);
          this.serverError.set(
            'Could not create the hypothesis. Check the fields and try again.',
          );
        },
      });
  }
}
