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
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import {
  rxResource,
  takeUntilDestroyed,
  toSignal,
} from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map, startWith } from 'rxjs';
import { ContentService } from '../../../../core/services/content.service';
import { NotificationService } from '../../../../core/services/notification.service';
import {
  AdminTopbarService,
  type TopbarAction,
} from '../../../admin-layout/admin-topbar.service';
import type {
  ApiContent,
  ApiUpdateContentRequest,
  ContentType,
} from '../../../../core/models/api.model';

interface ContentEditorForm {
  title: FormControl<string>;
  body: FormControl<string>;
  excerpt: FormControl<string>;
  type: FormControl<ContentType>;
  tags: FormControl<string>;
  coverImage: FormControl<string>;
  readingTimeMin: FormControl<number>;
  isPublic: FormControl<boolean>;
}

const CONTENT_TYPE_OPTIONS: readonly {
  value: ContentType;
  label: string;
}[] = [
  { value: 'article', label: 'Article' },
  { value: 'essay', label: 'Essay' },
  { value: 'build-log', label: 'Build Log' },
  { value: 'til', label: 'TIL' },
  { value: 'digest', label: 'Digest' },
];

/**
 * Content Editor — Editor route for the content lifecycle.
 *
 * Layout mirrors: markdown editor on the
 * left, metadata sidebar on the right. Topbar publishes the four action
 * buttons (Cancel / Save draft / Revert to draft / Publish) plus an
 * overflow menu (Send for review / Archive).
 *
 * Endpoints — `submit-for-review`, `revert-to-draft`, and `archive`
 * may not be live yet. The component tolerates 404 / 405 via
 * {@link handleMissingEndpoint}: the toast is explicit that the endpoint
 * is pending in the backend; the editor state does not change.
 *
 * Keyboard:
 *   ⌘S        — save draft
 *   ⌘⇧P       — publish (only while status='review')
 *   ⌘⇧R       — revert to draft (only while status='review')
 * All three preventDefault so browser shortcuts don't fire.
 */
@Component({
  selector: 'app-content-editor-page',
  standalone: true,
  imports: [ReactiveFormsModule, DatePipe],
  templateUrl: './content-editor.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class ContentEditorPageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly contentService = inject(ContentService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly typeOptions = CONTENT_TYPE_OPTIONS;

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly contentResource = rxResource<ApiContent, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.contentService.adminGet(params),
  });

  protected readonly content = this.contentResource.value;
  protected readonly isLoading = computed(
    () => this.contentResource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.contentResource.status() === 'error',
  );

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  protected readonly form = new FormGroup<ContentEditorForm>({
    title: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.maxLength(200)],
    }),
    body: new FormControl('', { nonNullable: true }),
    excerpt: new FormControl('', { nonNullable: true }),
    type: new FormControl<ContentType>('article', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    tags: new FormControl('', { nonNullable: true }),
    coverImage: new FormControl('', { nonNullable: true }),
    readingTimeMin: new FormControl(0, { nonNullable: true }),
    isPublic: new FormControl(false, { nonNullable: true }),
  });

  // Bridge Angular FormGroup state to signals so the topbar effect re-runs
  // when the user types or resets the form. `form.dirty` / `form.invalid`
  // are not reactive by themselves.
  private readonly formStatus = toSignal(
    this.form.statusChanges.pipe(startWith(this.form.status)),
    { initialValue: this.form.status },
  );
  private readonly formDirty = toSignal(
    this.form.events.pipe(map(() => this.form.dirty)),
    { initialValue: this.form.dirty },
  );

  constructor() {
    // Hydrate form when content arrives.
    effect(() => {
      const c = this.content();
      if (!c) return;
      this.form.reset(
        {
          title: c.title,
          body: c.body,
          excerpt: c.excerpt,
          type: c.type,
          tags: (c.tags ?? []).join(', '),
          coverImage: c.cover_image ?? '',
          readingTimeMin: c.reading_time_min,
          isPublic: c.is_public,
        },
        { emitEvent: false },
      );
    });

    // Push topbar context whenever content status changes.
    effect(() => this.topbar.set(this.buildTopbarContext()));

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  private buildTopbarContext() {
    const c = this.content();
    // Read form-state signals so the effect re-runs on user input.
    const formStatus = this.formStatus();
    const formDirty = this.formDirty();
    const formInvalid = formStatus === 'INVALID';

    const title = c ? `Editing · ${c.type}` : 'Content editor';
    const crumbs = c
      ? ['Knowledge', 'Content', c.id.slice(0, 8)]
      : ['Knowledge', 'Content'];

    const actions: TopbarAction[] = [
      {
        id: 'cancel',
        label: 'Cancel',
        kind: 'secondary',
        run: () => this.cancel(),
      },
      {
        id: 'save',
        label: 'Save draft',
        kind: 'primary',
        shortcutHint: '⌘S',
        disabled: !c || this.isActioning() || formInvalid,
        run: () => this.save(),
      },
    ];

    if (c?.status === 'review') {
      actions.push({
        id: 'revert',
        label: 'Revert to draft',
        kind: 'secondary',
        shortcutHint: '⌘⇧R',
        disabled: this.isActioning(),
        run: () => this.revertToDraft(),
      });
      actions.push({
        id: 'publish',
        label: 'Publish (human only)',
        kind: 'primary',
        shortcutHint: '⌘⇧P',
        disabled: this.isActioning(),
        run: () => this.publish(),
      });
    }

    const overflowActions: TopbarAction[] = [];
    if (c?.status === 'draft') {
      overflowActions.push({
        id: 'submit-review',
        label: 'Send for review',
        kind: 'secondary',
        disabled: this.isActioning() || formDirty,
        run: () => this.submitForReview(),
      });
    }
    if (c && c.status !== 'archived') {
      overflowActions.push({
        id: 'archive',
        label: 'Archive',
        kind: 'destructive',
        disabled: this.isActioning(),
        run: () => this.archiveContent(),
      });
    }

    return { title, crumbs, actions, overflowActions };
  }

  protected cancel(): void {
    this.router.navigate(['/admin/knowledge/content']);
  }

  protected save(): void {
    const c = this.content();
    if (!c || this.form.invalid || this._isActioning()) return;

    const v = this.form.getRawValue();
    const body: ApiUpdateContentRequest = {
      title: v.title.trim(),
      body: v.body,
      excerpt: v.excerpt,
      tags: parseTags(v.tags),
      cover_image: v.coverImage || undefined,
      reading_time_min: v.readingTimeMin,
      is_public: v.isPublic,
    };

    this._isActioning.set(true);
    this.contentService
      .update(c.id, body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.form.markAsPristine();
          this.notifications.success('Draft saved.');
          this.contentResource.reload();
        },
        error: () => {
          this._isActioning.set(false);
          this.notifications.error('Failed to save draft.');
        },
      });
  }

  protected submitForReview(): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    this.contentService
      .submitForReview(c.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success('Sent for review.');
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          this.handleMissingEndpoint(err, 'submit-for-review');
        },
      });
  }

  protected revertToDraft(): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    this.contentService
      .revertToDraft(c.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success('Reverted to draft.');
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          this.handleMissingEndpoint(err, 'revert-to-draft');
        },
      });
  }

  protected publish(): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    this.contentService
      .publish(c.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(`Published "${c.title}".`);
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          const status = httpStatus(err);
          if (status === 403) {
            this.notifications.error(
              'Only human callers can publish; action refused.',
            );
          } else {
            this.notifications.error('Failed to publish.');
          }
        },
      });
  }

  protected archiveContent(): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    this.contentService
      .archive(c.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(`Archived "${c.title}".`);
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          this.handleMissingEndpoint(err, 'archive');
        },
      });
  }

  /**
   * A 404/405/501 on a endpoint means the backend has not yet landed
   * it (405 = route exists but wrong verb; 501 = gateway returns "Not
   * Implemented"). Surface a clear info toast rather than a generic
   * failure so the operator knows the UI is ready and the API is
   * pending.
   */
  private handleMissingEndpoint(err: unknown, name: string): void {
    const status = httpStatus(err);
    if (status === 404 || status === 405 || status === 501) {
      this.notifications.info(
        `Endpoint not yet available in backend (${name}).`,
      );
      return;
    }
    this.notifications.error(`Failed to ${name.replace('-', ' ')}.`);
  }

  /**
   * Host-level keyboard shortcuts. Modifier-bearing only, so a11y
   * single-character gates do not apply. Each handler preventDefaults
   * so the browser's built-in shortcut (⌘S save page, etc.) is
   * suppressed.
   */
  protected handleKeydown(event: KeyboardEvent): void {
    const isCmdOrCtrl = event.metaKey || event.ctrlKey;
    if (!isCmdOrCtrl) return;

    // Bail if the component is not yet hydrated — there's nothing to
    // act on, and avoids firing during late-arriving events that reach
    // a torn-down view.
    const c = this.content();
    if (!c) return;

    // ⌘S — save draft
    if (event.key === 's' && !event.shiftKey && !event.altKey) {
      event.preventDefault();
      this.save();
      return;
    }

    // Below: remaining chords all require Cmd+Shift without Alt, and
    // only apply while the content is in review.
    if (!event.shiftKey || event.altKey) return;
    if (c.status !== 'review') return;

    // ⌘⇧P — publish. `event.key` is guaranteed uppercase when Shift is
    // held, independent of Caps Lock.
    if (event.key === 'P') {
      event.preventDefault();
      this.publish();
      return;
    }
    // ⌘⇧R — revert to draft
    if (event.key === 'R') {
      event.preventDefault();
      this.revertToDraft();
    }
  }

  /**
   * True when the form has unsaved edits. Used by the
   * {@link contentEditorCanDeactivate} route guard to confirm before
   * leaving the page.
   */
  readonly hasUnsavedChanges = this.formDirty;

  protected aiSummary(c: ApiContent): string | null {
    const v = c.ai_metadata?.['summary'];
    return typeof v === 'string' && v.length > 0 ? v : null;
  }

  protected aiQualityScore(c: ApiContent): number | null {
    const v = c.ai_metadata?.['quality_score'];
    return typeof v === 'number' ? v : null;
  }
}

function parseTags(raw: string): string[] {
  return raw
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

function httpStatus(err: unknown): number | null {
  return err instanceof HttpErrorResponse ? err.status : null;
}
