import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { HttpErrorResponse } from '@angular/common/http';
import { Router, RouterLink } from '@angular/router';
import {
  form,
  FormField,
  required,
  maxLength,
  validate,
} from '@angular/forms/signals';
import {
  PlanService,
  type AreaCreateRequest,
} from '../../../../core/services/plan.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

interface AreaForm {
  name: string;
  description: string;
}

const NAME_MAX = 60;
const NAME_BLANK = 'A name is required.';
const NAME_NO_SLUG =
  'Use at least one letter or number — the slug is derived from this.';

/** Mirror the server's slug derivation so the preview matches the result. */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/**
 * Area create — Signal Forms. Name is required (max 60) and must contain at
 * least one slug-able character; the slug itself is NOT a form field — the
 * server derives it from the name. A live preview shows what the derived
 * slug will be. Description is optional. On success the page returns to the
 * area list. A 409 surfaces a duplicate-slug message, a 400 a generic
 * bad-request message.
 */
@Component({
  selector: 'app-area-create-page',
  imports: [RouterLink, FormField],
  templateUrl: './area-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class AreaCreatePageComponent {
  private readonly planService = inject(PlanService);
  private readonly router = inject(Router);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly nameMax = NAME_MAX;
  protected readonly submitting = signal(false);
  protected readonly submitted = signal(false);
  protected readonly serverError = signal<string | null>(null);

  protected readonly model = signal<AreaForm>({
    name: '',
    description: '',
  });

  // Live preview of the slug the server will derive from the name.
  protected readonly slugPreview = computed(() =>
    slugify(this.model().name),
  );

  protected readonly areaForm = form(this.model, (path) => {
    required(path.name, { message: NAME_BLANK });
    maxLength(path.name, NAME_MAX, {
      message: `Keep it under ${NAME_MAX} characters.`,
    });
    // A name made only of separators / control chars produces no slug — the
    // server rejects that with a 400, so block it client-side too.
    validate(path.name, ({ value }) => {
      const text = value();
      return text.trim().length > 0 && slugify(text).length === 0
        ? { kind: 'noSlug', message: NAME_NO_SLUG }
        : undefined;
    });
  });

  constructor() {
    this.topbar.set({
      title: 'New area',
      crumbs: ['Commitment', 'Areas', 'New'],
    });
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

    if (this.areaForm().invalid()) {
      this.submitted.set(true);
      this.notifications.error('Fix the highlighted fields');
      return;
    }

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    // NO slug in the body — the server derives it from the name.
    const body: AreaCreateRequest = {
      name: v.name.trim(),
      description: v.description.trim(),
    };

    this.planService
      .createArea(body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notifications.success('Area created');
          this.router.navigate(['/admin/commitment/areas']);
        },
        error: (err: unknown) => {
          this.submitting.set(false);
          this.serverError.set(this.messageFor(err));
        },
      });
  }

  private messageFor(err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      if (err.status === 409) {
        return 'An area with this slug already exists. Choose a different name.';
      }
      if (err.status === 400) {
        return 'That name can’t be turned into a slug. Use letters or numbers.';
      }
    }
    return 'Could not create the area. Check the fields and try again.';
  }
}
