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
  pattern,
} from '@angular/forms/signals';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface DomainForm {
  slug: string;
  name: string;
}

const SLUG_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;

/**
 * Domain create — a learning ontology root. Slug is the stable identifier
 * (lowercase kebab-case) and name is the human label. Both required. Signal
 * Forms, mirroring the Goal create form.
 */
@Component({
  selector: 'app-domain-create-page',
  standalone: true,
  imports: [RouterLink, FormField],
  templateUrl: './domain-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class DomainCreatePageComponent {
  private readonly learningService = inject(LearningService);
  private readonly router = inject(Router);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly submitting = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly model = signal<DomainForm>({
    slug: '',
    name: '',
  });

  protected readonly domainForm = form(this.model, (path) => {
    required(path.slug, { message: 'A slug is required' });
    pattern(path.slug, SLUG_PATTERN, {
      message: 'Lowercase kebab-case: letters, numbers, single hyphens',
    });
    required(path.name, { message: 'A name is required' });
    maxLength(path.name, 100, {
      message: 'Name must be 100 characters or fewer',
    });
  });

  constructor() {
    this.topbar.set({
      title: 'New domain',
      crumbs: ['Learning', 'Domains', 'New'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected save(): void {
    if (this.domainForm().invalid() || this.submitting()) return;

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    this.learningService
      .createDomain({
        slug: v.slug.trim(),
        name: v.name.trim(),
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.router.navigate(['/admin/learning/domains']),
        error: () => {
          this.submitting.set(false);
          this.serverError.set(
            'Could not create the domain. Check the fields and try again.',
          );
        },
      });
  }
}
