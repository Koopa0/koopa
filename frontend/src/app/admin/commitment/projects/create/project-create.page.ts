import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { HttpErrorResponse } from '@angular/common/http';
import { Router, RouterLink } from '@angular/router';
import {
  form,
  FormField,
  required,
  maxLength,
  validate,
  minLengthError,
  pattern,
} from '@angular/forms/signals';
import {
  PlanService,
  type Area,
  type ProjectCreateRequest,
} from '../../../../core/services/plan.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { GoalSummary } from '../../../../core/models/admin.model';

interface ProjectForm {
  title: string;
  slug: string;
  description: string;
  area_id: string;
  goal_id: string;
}

const TITLE_MAX = 90;
const TITLE_MIN = 4;
const TITLE_TOO_SHORT = 'Give it at least 4 characters.';
const SLUG_MAX = 80;
// Hyphen-separated segments with no whitespace, slash, or leading/trailing/
// consecutive hyphens. Unicode letters/numbers (incl. CJK) are allowed — slugs
// carry UTF-8 fine in URLs — mirroring the server's chk_*_slug_format.
const SLUG_PATTERN = /^[^\s/-]+(?:-[^\s/-]+)*$/;
const SLUG_INVALID =
  'No spaces or slashes, and no leading, trailing, or doubled hyphens (e.g. knowledge-engine or 知識引擎).';

/** Derive a URL slug from free text — the same shape the server expects. */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, SLUG_MAX);
}

/**
 * Project create — Signal Forms. Title and slug are required; the slug is
 * EXPLICIT (unlike goals, whose slug is derived server-side) but is
 * auto-suggested from the title until the user edits it by hand, after
 * which it stays under manual control. Description, area, and goal are
 * optional. Status is server-set (`in_progress`) and never part of the
 * form. An invalid submit raises the banner and a toast; a 409 from the
 * server surfaces a slug-conflict message.
 */
@Component({
  selector: 'app-project-create-page',
  imports: [RouterLink, FormField],
  templateUrl: './project-create.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ProjectCreatePageComponent {
  private readonly planService = inject(PlanService);
  private readonly router = inject(Router);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly titleMax = TITLE_MAX;
  protected readonly slugMax = SLUG_MAX;
  protected readonly submitting = signal(false);
  protected readonly submitted = signal(false);
  protected readonly serverError = signal<string | null>(null);

  // Once the user types in the slug field, stop auto-suggesting from title.
  private readonly slugEdited = signal(false);

  // Area selector is optional — a failed/empty areas read just leaves the
  // select with its "no area" placeholder; it never blocks creation. The
  // server treats a NULL `area_id` as unclassified.
  private readonly areasResource = rxResource<Area[], void>({
    stream: () => this.planService.getAreas(),
  });
  protected readonly areas = computed<Area[]>(() =>
    this.areasResource.hasValue() ? this.areasResource.value() : [],
  );

  // Goal selector is optional — a failed/empty goals read just leaves the
  // select with its "no goal" placeholder; it never blocks creation. The
  // server links the project to the goal via `goal_id`.
  private readonly goalsResource = rxResource<GoalSummary[], void>({
    stream: () => this.planService.getGoalsOverview(),
  });
  protected readonly goals = computed<GoalSummary[]>(() =>
    this.goalsResource.hasValue() ? this.goalsResource.value() : [],
  );

  protected readonly model = signal<ProjectForm>({
    title: '',
    slug: '',
    description: '',
    area_id: '',
    goal_id: '',
  });

  protected readonly projectForm = form(this.model, (path) => {
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

    required(path.slug, { message: 'A slug is required.' });
    maxLength(path.slug, SLUG_MAX, {
      message: `Keep it under ${SLUG_MAX} characters.`,
    });
    pattern(path.slug, SLUG_PATTERN, { message: SLUG_INVALID });
  });

  constructor() {
    this.topbar.set({
      title: 'New project',
      crumbs: ['Commitment', 'Projects', 'New'],
    });

    // Keep the slug in lock-step with the title until the user takes over.
    effect(() => {
      const title = this.projectForm.title().value();
      if (this.slugEdited()) return;
      const suggested = slugify(title);
      if (this.model().slug !== suggested) {
        this.model.update((m) => ({ ...m, slug: suggested }));
      }
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

  /** Mark the slug as manually owned so the auto-suggest stops. */
  protected onSlugInput(): void {
    this.slugEdited.set(true);
  }

  protected save(): void {
    if (this.submitting()) return;

    if (this.projectForm().invalid()) {
      this.submitted.set(true);
      this.notifications.error('Fix the highlighted fields');
      return;
    }

    const v = this.model();
    this.submitting.set(true);
    this.serverError.set(null);

    const body: ProjectCreateRequest = {
      title: v.title.trim(),
      slug: v.slug.trim(),
    };
    // Optional fields are sent only when present so the server applies its
    // own defaults (status=in_progress) / leaves the FK NULL (area_id NULL =
    // unclassified, goal_id NULL = unlinked).
    if (v.description.trim()) body.description = v.description.trim();
    if (v.area_id) body.area_id = v.area_id;
    if (v.goal_id) body.goal_id = v.goal_id;

    this.planService
      .createProject(body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (project) => {
          this.notifications.success(
            'Project created · status set to in_progress',
          );
          this.router.navigate(['/admin/commitment/projects', project.id]);
        },
        error: (err: unknown) => {
          this.submitting.set(false);
          this.serverError.set(this.messageFor(err));
        },
      });
  }

  private messageFor(err: unknown): string {
    if (err instanceof HttpErrorResponse && err.status === 409) {
      return 'That slug is already taken. Choose a different one.';
    }
    return 'Could not create the project. Check the fields and try again.';
  }
}
