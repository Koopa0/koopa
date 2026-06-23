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
import { TopicService } from '../../../../core/services/topic.service';
import { NotificationService } from '../../../../core/services/notification.service';
import {
  AdminTopbarService,
  type TopbarAction,
} from '../../../admin-layout/admin-topbar.service';
import { StatusBadgeComponent } from '../../../../shared/components/status-badge/status-badge.component';
import type { BadgeVariant } from '../../../../shared/components/status-badge/status-badge.component';
import {
  ContentLifecycleRailComponent,
  type ContentLifecycleAction,
} from './lifecycle-rail.component';
import { ContentPreviewOverlayComponent } from './preview-overlay.component';
import { SendBackReasonDialogComponent } from './send-back-reason-dialog.component';
import type {
  ApiContent,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
  ContentStatus,
  ContentType,
} from '../../../../core/models/api.model';

interface ContentEditorForm {
  slug: FormControl<string>;
  title: FormControl<string>;
  body: FormControl<string>;
  excerpt: FormControl<string>;
  type: FormControl<ContentType>;
  coverImage: FormControl<string>;
  readingTimeMin: FormControl<number>;
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

const STATUS_BADGE_VARIANT: Record<ContentStatus, BadgeVariant> = {
  draft: 'neutral',
  review: 'warning',
  changes_requested: 'warning',
  published: 'success',
  archived: 'neutral',
};

// Hyphen-separated segments, no whitespace/slash, no leading/trailing/doubled
// hyphens. Unicode letters/numbers (incl. CJK) allowed — mirrors the server's
// chk_content_slug_format; slugs carry UTF-8 fine in URLs.
const SLUG_PATTERN = /^[^\s/-]+(?:-[^\s/-]+)*$/;
const WORDS_PER_MINUTE = 220;

/**
 * Content Editor — create + edit route for the content lifecycle.
 *
 * Create mode (`/new`, no :id): empty form, slug editable; saving POSTs
 * the new content (status defaults to draft server-side) and navigates
 * to the `:id/edit` route of the created record.
 *
 * Edit mode (`:id/edit`): markdown editor on the left; the sidebar
 * carries the lifecycle rail (draft → review → published → archived
 * with the legal transition buttons), the is_public switch (PATCH
 * …/is-public), and the type/topics metadata column. Publishing
 * is human-only server-side — a 403 surfaces as a refusal toast.
 *
 * Keyboard:
 *   ⌘S        — save (create or update)
 *   ⌘⇧P       — publish (only while status='review')
 *   ⌘⇧R       — revert to draft (only while status='review')
 */
@Component({
  selector: 'app-content-editor-page',
  imports: [
    ReactiveFormsModule,
    DatePipe,
    StatusBadgeComponent,
    ContentLifecycleRailComponent,
    ContentPreviewOverlayComponent,
    SendBackReasonDialogComponent,
  ],
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
  private readonly topicService = inject(TopicService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly typeOptions = CONTENT_TYPE_OPTIONS;

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id'))),
    { initialValue: null },
  );

  /** Create mode when the route carries no :id. */
  protected readonly isCreate = computed(() => this.idFromRoute() === null);

  protected readonly contentResource = rxResource<
    ApiContent,
    string | undefined
  >({
    params: () => this.idFromRoute() ?? undefined,
    stream: ({ params }) => this.contentService.adminGet(params),
  });

  protected readonly content = this.contentResource.value;
  protected readonly isLoading = computed(
    () => this.contentResource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.contentResource.status() === 'error',
  );

  // The editor picker must offer every topic, including ones with no published
  // content yet, so a draft can be filed under a fresh topic. adminList() is the
  // all-topics endpoint; getAllTopics() (public) hides empty categories.
  protected readonly topicsResource = rxResource({
    stream: () => this.topicService.adminList(),
  });
  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). Without this guard a
  // failed topics fetch throws here instead of falling back to an empty list.
  protected readonly topics = computed(() =>
    this.topicsResource.hasValue() ? this.topicsResource.value() : [],
  );

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  /** Publish-preview overlay visibility (edit mode, saved content only). */
  protected readonly showPreview = signal(false);

  /** Send-back reason dialog visibility. */
  protected readonly showSendBackDialog = signal(false);

  /** Selected topic ids; kept outside the FormGroup so toggling stays a plain signal write. */
  protected readonly selectedTopicIds = signal<string[]>([]);

  protected readonly form = new FormGroup<ContentEditorForm>({
    slug: new FormControl('', { nonNullable: true }),
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
    coverImage: new FormControl('', { nonNullable: true }),
    readingTimeMin: new FormControl(0, { nonNullable: true }),
  });

  // Bridge Angular FormGroup state to signals so effects re-run when
  // the user types or resets the form. `form.dirty` / `form.invalid`
  // are not reactive by themselves.
  private readonly formStatus = toSignal(
    this.form.statusChanges.pipe(startWith(this.form.status)),
    { initialValue: this.form.status },
  );
  private readonly formDirty = toSignal(
    this.form.events.pipe(map(() => this.form.dirty)),
    { initialValue: this.form.dirty },
  );

  // Mirrors of form values that the template derives display state
  // from. Updated by valueChanges and re-seeded on hydrate (form.reset
  // suppresses events, so the hydrate effect writes them directly).
  private readonly bodyText = signal('');
  protected readonly typeValue = signal<ContentType>('article');

  protected readonly wordCount = computed(() => {
    const t = this.bodyText().trim();
    return t.length === 0 ? 0 : t.split(/\s+/).length;
  });
  protected readonly minRead = computed(() =>
    Math.max(1, Math.round(this.wordCount() / WORDS_PER_MINUTE)),
  );

  protected readonly saveState = computed<
    'saving' | 'dirty' | 'new' | 'saved'
  >(() => {
    if (this.isActioning()) return 'saving';
    if (this.formDirty()) return 'dirty';
    return this.isCreate() ? 'new' : 'saved';
  });

  /**
   * True when the form has unsaved edits. Used by the
   * {@link contentEditorCanDeactivate} route guard to confirm before
   * leaving the page — in create and edit mode alike.
   */
  readonly hasUnsavedChanges = this.formDirty;

  constructor() {
    if (this.isCreate()) {
      this.form.controls.slug.addValidators([
        Validators.required,
        Validators.pattern(SLUG_PATTERN),
      ]);
      this.form.controls.slug.updateValueAndValidity();
    }

    this.form.controls.body.valueChanges
      .pipe(takeUntilDestroyed())
      .subscribe((v) => this.bodyText.set(v));
    this.form.controls.type.valueChanges
      .pipe(takeUntilDestroyed())
      .subscribe((v) => this.typeValue.set(v));

    // Hydrate form when content arrives (edit mode only).
    effect(() => {
      const c = this.content();
      if (!c) return;
      this.form.reset(
        {
          slug: c.slug,
          title: c.title,
          body: c.body,
          excerpt: c.excerpt,
          type: c.type,
          coverImage: c.cover_image ?? '',
          readingTimeMin: c.reading_time_min,
        },
        { emitEvent: false },
      );
      this.bodyText.set(c.body);
      this.typeValue.set(c.type);
      this.selectedTopicIds.set((c.topics ?? []).map((t) => t.id));
    });

    effect(() => this.topbar.set(this.buildTopbarContext()));

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  private buildTopbarContext() {
    const c = this.content();
    const create = this.isCreate();
    const formInvalid = this.formStatus() === 'INVALID';

    const actions: TopbarAction[] = [
      ...(!create && c
        ? [
            {
              id: 'preview',
              label: 'Preview',
              kind: 'secondary',
              run: () => this.showPreview.set(true),
            } satisfies TopbarAction,
          ]
        : []),
      {
        id: 'close',
        label: 'Close',
        kind: 'secondary',
        run: () => this.cancel(),
      },
      {
        id: 'save',
        label: create ? 'Create draft' : 'Save',
        kind: 'primary',
        shortcutHint: '⌘S',
        disabled: this.isActioning() || formInvalid || (!create && !c),
        run: () => this.save(),
      },
    ];

    return {
      title: create ? 'New content' : c ? `Editing · ${c.type}` : 'Content editor',
      crumbs: create
        ? ['Knowledge', 'Content', 'New']
        : c
          ? ['Knowledge', 'Content', c.id.slice(0, 8)]
          : ['Knowledge', 'Content'],
      actions,
    };
  }

  protected cancel(): void {
    this.router.navigate(['/admin/knowledge/content']);
  }

  protected save(): void {
    if (this._isActioning()) return;
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    if (this.isCreate()) {
      this.createContent();
    } else {
      this.updateContent();
    }
  }

  private createContent(): void {
    const v = this.form.getRawValue();
    const body: ApiCreateContentRequest = {
      slug: v.slug.trim(),
      title: v.title.trim(),
      type: v.type,
      body: v.body,
      excerpt: v.excerpt,
      topic_ids: this.selectedTopicIds(),
      cover_image: v.coverImage || undefined,
      reading_time_min: v.readingTimeMin,
    };

    this._isActioning.set(true);
    this.contentService
      .create(body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (created) => {
          this._isActioning.set(false);
          this.form.markAsPristine();
          this.notifications.success(`Draft "${created.title}" created.`);
          this.router.navigate([
            '/admin/knowledge/content',
            created.id,
            'edit',
          ]);
        },
        error: () => {
          this._isActioning.set(false);
          this.notifications.error('Failed to create content.');
        },
      });
  }

  private updateContent(): void {
    const c = this.content();
    if (!c) return;

    const v = this.form.getRawValue();
    const body: ApiUpdateContentRequest = {
      title: v.title.trim(),
      body: v.body,
      excerpt: v.excerpt,
      topic_ids: this.selectedTopicIds(),
      cover_image: v.coverImage || undefined,
      reading_time_min: v.readingTimeMin,
      // Visibility is owned by the PATCH …/is-public switch; echo the
      // server-known value so the full update does not clobber it.
      is_public: c.is_public,
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

  protected runLifecycleAction(action: ContentLifecycleAction): void {
    switch (action) {
      case 'submit-for-review':
        this.submitForReview();
        break;
      case 'publish':
        this.publish();
        break;
      case 'send-back':
        this.showSendBackDialog.set(true);
        break;
      case 'revert-to-draft':
        this.revertToDraft();
        break;
      case 'archive':
        this.archiveContent();
        break;
    }
  }

  protected submitForReview(): void {
    this.transition(
      (id) => this.contentService.submitForReview(id),
      'Submitted for review.',
      'submit-for-review',
    );
  }

  protected revertToDraft(): void {
    this.transition(
      (id) => this.contentService.revertToDraft(id),
      'Reverted to draft.',
      'revert-to-draft',
    );
  }

  protected archiveContent(): void {
    this.transition(
      (id) => this.contentService.archive(id),
      'Archived.',
      'archive',
    );
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
          if (httpStatus(err) === 403) {
            this.notifications.error(
              'Only human callers can publish; action refused.',
            );
          } else {
            this.notifications.error('Failed to publish.');
          }
        },
      });
  }

  protected sendBack(reviewNote: string): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    this.contentService
      .sendBack(c.id, reviewNote)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.showSendBackDialog.set(false);
          this.notifications.success('Sent back for revision.');
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          this.handleTransitionError(err, 'send-back');
        },
      });
  }

  /** Shared runner for the non-publish lifecycle POSTs. */
  private transition(
    call: (id: string) => ReturnType<ContentService['archive']>,
    successMessage: string,
    name: string,
  ): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    this._isActioning.set(true);
    call(c.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(successMessage);
          this.contentResource.reload();
        },
        error: (err: unknown) => {
          this._isActioning.set(false);
          this.handleTransitionError(err, name);
        },
      });
  }

  protected toggleVisibility(): void {
    const c = this.content();
    if (!c || this._isActioning()) return;

    const next = !c.is_public;
    this._isActioning.set(true);
    this.contentService
      .setVisibility(c.id, next)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(next ? 'Set public.' : 'Set private.');
          this.contentResource.reload();
        },
        error: () => {
          this._isActioning.set(false);
          this.notifications.error('Failed to change visibility.');
        },
      });
  }

  protected toggleTopic(id: string): void {
    this.selectedTopicIds.update((ids) =>
      ids.includes(id) ? ids.filter((t) => t !== id) : [...ids, id],
    );
    this.form.markAsDirty();
  }

  /**
   * Surface a failed lifecycle action as an error toast. The backend
   * routes exist, so a 404/405/501 here is an unexpected failure (a
   * routing/proxy mismatch or a missing record) — the message tells
   * the operator to refresh and retry.
   */
  private handleTransitionError(err: unknown, name: string): void {
    const status = httpStatus(err);
    const verb = name.replaceAll('-', ' ');
    if (status === 404 || status === 405 || status === 501) {
      this.notifications.error(
        `Could not ${verb} — please refresh and try again.`,
      );
      return;
    }
    this.notifications.error(`Failed to ${verb}.`);
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

    // ⌘S — save (create or update)
    if (event.key === 's' && !event.shiftKey && !event.altKey) {
      event.preventDefault();
      this.save();
      return;
    }

    // Below: remaining chords all require Cmd+Shift without Alt, and
    // only apply while the content is in review.
    if (!event.shiftKey || event.altKey) return;
    const c = this.content();
    if (c?.status !== 'review') return;

    // `event.key` is guaranteed uppercase when Shift is held,
    // independent of Caps Lock.
    if (event.key === 'P') {
      event.preventDefault();
      this.publish();
      return;
    }
    if (event.key === 'R') {
      event.preventDefault();
      this.revertToDraft();
    }
  }

  protected statusVariant(status: ContentStatus): BadgeVariant {
    return STATUS_BADGE_VARIANT[status];
  }

  protected aiSummary(c: ApiContent): string | null {
    const v = c.ai_metadata?.['summary'];
    return typeof v === 'string' && v.length > 0 ? v : null;
  }

  protected aiQualityScore(c: ApiContent): number | null {
    const v = c.ai_metadata?.['quality_score'];
    return typeof v === 'number' ? v : null;
  }
}

function httpStatus(err: unknown): number | null {
  return err instanceof HttpErrorResponse ? err.status : null;
}
