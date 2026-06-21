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
import {
  NoteService,
  type NoteCreateRequest,
  type NoteDetail,
  type NoteUpdateRequest,
} from '../../../../core/services/note.service';
import { NotificationService } from '../../../../core/services/notification.service';
import {
  AdminTopbarService,
  type TopbarAction,
} from '../../../admin-layout/admin-topbar.service';
import type { NoteKind, NoteMaturity } from '../../../../core/models/api.model';

interface NoteEditorForm {
  slug: FormControl<string>;
  title: FormControl<string>;
  body: FormControl<string>;
  kind: FormControl<NoteKind>;
}

const KIND_OPTIONS: readonly { value: NoteKind; label: string }[] = [
  { value: 'solve-note', label: 'Solve note' },
  { value: 'concept-note', label: 'Concept note' },
  { value: 'debug-postmortem', label: 'Debug postmortem' },
  { value: 'decision-log', label: 'Decision log' },
  { value: 'reading-note', label: 'Reading note' },
  { value: 'musing', label: 'Musing' },
];

const MATURITY_LADDER: readonly NoteMaturity[] = [
  'seed',
  'stub',
  'evergreen',
  'needs_revision',
  'archived',
];

const MATURITY_LABEL: Record<NoteMaturity, string> = {
  seed: 'Seed',
  stub: 'Stub',
  evergreen: 'Evergreen',
  needs_revision: 'Needs revision',
  archived: 'Archived',
};

const MATURITY_DOT: Record<NoteMaturity, string> = {
  seed: 'bg-fg-subtle',
  stub: 'bg-info',
  evergreen: 'bg-success',
  needs_revision: 'bg-warn',
  archived: 'bg-fg-faint',
};

// Hyphen-separated segments, no whitespace/slash, no leading/trailing/doubled
// hyphens. Unicode letters/numbers (incl. CJK) allowed — mirrors the server's
// chk_note_slug_format; slugs carry UTF-8 fine in URLs.
const SLUG_PATTERN = /^[^\s/-]+(?:-[^\s/-]+)*$/;

/**
 * Note Editor — create + edit route for Zettelkasten notes.
 *
 * Create mode (`/new`, no :id): empty form with slug/title/body/kind;
 * saving POSTs the note (maturity defaults server-side) and navigates
 * to the created note's `:id/edit` route.
 *
 * Edit mode (`:id/edit`): markdown body on the left, metadata +
 * maturity ladder on the right. Maturity transitions go through the
 * dedicated POST …/maturity endpoint, never the general update;
 * backward moves (e.g. evergreen → stub) ask for confirmation.
 */
@Component({
  selector: 'app-note-editor-page',
  imports: [ReactiveFormsModule, DatePipe],
  templateUrl: './note-editor.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class NoteEditorPageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly noteService = inject(NoteService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly kindOptions = KIND_OPTIONS;
  protected readonly maturityLadder = MATURITY_LADDER;

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id'))),
    { initialValue: null },
  );

  /** Create mode when the route carries no :id. */
  protected readonly isCreate = computed(() => this.idFromRoute() === null);

  protected readonly noteResource = rxResource<NoteDetail, string | undefined>({
    params: () => this.idFromRoute() ?? undefined,
    stream: ({ params }) => this.noteService.get(params),
  });

  protected readonly note = computed(() => this.noteResource.value());
  protected readonly isLoading = computed(
    () => this.noteResource.status() === 'loading' && !this.note(),
  );
  protected readonly hasError = computed(
    () => this.noteResource.status() === 'error',
  );
  protected readonly endpointsUnavailable = computed(() => {
    if (this.noteResource.status() !== 'error') return false;
    const err = this.noteResource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  protected readonly form = new FormGroup<NoteEditorForm>({
    slug: new FormControl('', { nonNullable: true }),
    title: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.maxLength(200)],
    }),
    body: new FormControl('', { nonNullable: true }),
    kind: new FormControl<NoteKind>('solve-note', {
      nonNullable: true,
      validators: [Validators.required],
    }),
  });

  private readonly formStatus = toSignal(
    this.form.statusChanges.pipe(startWith(this.form.status)),
    { initialValue: this.form.status },
  );
  private readonly formDirty = toSignal(
    this.form.events.pipe(map(() => this.form.dirty)),
    { initialValue: this.form.dirty },
  );

  /** Read by the canDeactivate guard — applies in create and edit mode alike. */
  readonly hasUnsavedChanges = computed(() => this.formDirty());

  constructor() {
    if (this.isCreate()) {
      // The create endpoint requires slug + body alongside title + kind.
      this.form.controls.slug.addValidators([
        Validators.required,
        Validators.pattern(SLUG_PATTERN),
      ]);
      this.form.controls.body.addValidators([Validators.required]);
      this.form.controls.slug.updateValueAndValidity();
      this.form.controls.body.updateValueAndValidity();
    }

    // Hydrate form whenever a fresh note arrives (edit mode only).
    effect(() => {
      const n = this.note();
      if (!n) return;
      this.form.reset(
        {
          slug: n.slug,
          title: n.title,
          body: n.body,
          kind: n.kind,
        },
        { emitEvent: false },
      );
    });

    // Seed topbar synchronously; effect rehydrates on state changes.
    this.topbar.set({
      title: 'Note editor',
      crumbs: ['Knowledge', 'Notes'],
    });
    effect(() => this.topbar.set(this.buildTopbarContext()));

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  private buildTopbarContext() {
    const n = this.note();
    const create = this.isCreate();
    const formInvalid = this.formStatus() === 'INVALID';
    const actioning = this.isActioning();

    const actions: TopbarAction[] = [
      {
        id: 'close',
        label: 'Close',
        kind: 'secondary',
        run: () => this.cancel(),
      },
      {
        id: 'save',
        label: create ? 'Create note' : 'Save',
        kind: 'primary',
        shortcutHint: '⌘S',
        disabled: actioning || formInvalid || (!create && !n),
        run: () => this.save(),
      },
    ];

    const overflowActions: TopbarAction[] = [];
    if (n) {
      overflowActions.push({
        id: 'delete',
        label: 'Delete note',
        kind: 'destructive',
        disabled: actioning,
        run: () => this.deleteNote(),
      });
    }

    return {
      title: create ? 'New note' : n ? `Editing · ${n.kind}` : 'Note editor',
      crumbs: create
        ? ['Knowledge', 'Notes', 'New']
        : n
          ? ['Knowledge', 'Notes', n.id.slice(0, 8)]
          : ['Knowledge', 'Notes'],
      actions,
      overflowActions,
    };
  }

  protected cancel(): void {
    this.router.navigate(['/admin/knowledge/notes']);
  }

  protected save(): void {
    if (this._isActioning()) return;
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    if (this.isCreate()) {
      this.createNote();
    } else {
      this.updateNote();
    }
  }

  private createNote(): void {
    const v = this.form.getRawValue();
    const body: NoteCreateRequest = {
      slug: v.slug.trim(),
      title: v.title.trim(),
      body: v.body,
      kind: v.kind,
    };

    this._isActioning.set(true);
    this.noteService
      .create(body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (created) => {
          this._isActioning.set(false);
          this.form.markAsPristine();
          this.notifications.success(`Note "${created.title}" created.`);
          this.router.navigate(['/admin/knowledge/notes', created.id, 'edit']);
        },
        error: () => {
          this._isActioning.set(false);
          this.notifications.error('Failed to create note.');
        },
      });
  }

  private updateNote(): void {
    const n = this.note();
    if (!n) return;

    const v = this.form.getRawValue();
    const body: NoteUpdateRequest = {
      title: v.title.trim(),
      body: v.body,
      kind: v.kind,
    };

    this._isActioning.set(true);
    this.noteService
      .update(n.id, body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.form.markAsPristine();
          this.notifications.success('Note saved.');
          this.noteResource.reload();
        },
        error: (err: unknown) => this.afterError(err, 'save'),
      });
  }

  protected setMaturity(maturity: NoteMaturity): void {
    const n = this.note();
    if (!n || this._isActioning() || maturity === n.maturity) return;

    const backwards =
      MATURITY_LADDER.indexOf(maturity) < MATURITY_LADDER.indexOf(n.maturity);
    if (backwards) {
      const ok =
        typeof window === 'undefined'
          ? true
          : window.confirm(
              `Move maturity backward from ${n.maturity} to ${maturity}? This is rare and the backend may warn.`,
            );
      if (!ok) return;
    }

    this._isActioning.set(true);
    this.noteService
      .updateMaturity(n.id, maturity)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success(
            `Maturity set to ${MATURITY_LABEL[maturity]}.`,
          );
          this.noteResource.reload();
        },
        error: (err: unknown) => this.afterError(err, 'update-maturity'),
      });
  }

  protected deleteNote(): void {
    const n = this.note();
    if (!n || this._isActioning()) return;

    const ok =
      typeof window === 'undefined'
        ? true
        : window.confirm(`Delete "${n.title}"? This cannot be undone.`);
    if (!ok) return;

    this._isActioning.set(true);
    this.noteService
      .remove(n.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isActioning.set(false);
          this.notifications.success('Note deleted.');
          this.router.navigate(['/admin/knowledge/notes']);
        },
        error: (err: unknown) => this.afterError(err, 'delete'),
      });
  }

  private afterError(err: unknown, name: string): void {
    this._isActioning.set(false);
    const status = err instanceof HttpErrorResponse ? err.status : null;
    const verb = name.replaceAll('-', ' ');
    if (status === 404 || status === 405 || status === 501) {
      this.notifications.error(
        `Could not ${verb} — please refresh and try again.`,
      );
      return;
    }
    this.notifications.error(`Failed to ${verb}.`);
  }

  protected maturityDotClass(m: NoteMaturity): string {
    return MATURITY_DOT[m];
  }

  protected maturityLabel(m: NoteMaturity): string {
    return MATURITY_LABEL[m];
  }

  /** ⌘S — save. (No publish / revert; notes have no publication.) */
  protected handleKeydown(event: KeyboardEvent): void {
    if (!(event.metaKey || event.ctrlKey)) return;
    if (event.shiftKey || event.altKey) return;
    if (event.key === 's') {
      event.preventDefault();
      this.save();
    }
  }
}
