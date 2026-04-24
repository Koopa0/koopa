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
  title: FormControl<string>;
  body: FormControl<string>;
  kind: FormControl<NoteKind>;
  conceptSlugs: FormControl<string>;
  targetIds: FormControl<string>;
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
  seed: 'bg-zinc-400',
  stub: 'bg-sky-400',
  evergreen: 'bg-emerald-500',
  needs_revision: 'bg-amber-400',
  archived: 'bg-zinc-600',
};

/**
 * Note Editor Two-column layout mirroring
 * the Content Editor: markdown body on the left, metadata + maturity
 * ladder + relations on the right.
 *
 * Save / Update maturity / Delete are  per ; callers tolerate
 * 404/405/501. Backward maturity transitions (e.g. evergreen → stub)
 * ask for confirmation because the backend warns on those moves per
 * the spec's "反向 transition" note.
 */
@Component({
  selector: 'app-note-editor-page',
  standalone: true,
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
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly noteResource = rxResource<NoteDetail, string>({
    params: () => this.idFromRoute(),
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
    title: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.maxLength(200)],
    }),
    body: new FormControl('', { nonNullable: true }),
    kind: new FormControl<NoteKind>('solve-note', {
      nonNullable: true,
      validators: [Validators.required],
    }),
    conceptSlugs: new FormControl('', { nonNullable: true }),
    targetIds: new FormControl('', { nonNullable: true }),
  });

  private readonly formStatus = toSignal(
    this.form.statusChanges.pipe(startWith(this.form.status)),
    { initialValue: this.form.status },
  );
  private readonly formDirty = toSignal(
    this.form.events.pipe(map(() => this.form.dirty)),
    { initialValue: this.form.dirty },
  );

  readonly hasUnsavedChanges = this.formDirty;

  constructor() {
    // Hydrate form whenever a fresh note arrives.
    effect(() => {
      const n = this.note();
      if (!n) return;
      this.form.reset(
        {
          title: n.title,
          body: n.body,
          kind: n.kind,
          conceptSlugs: n.concepts.map((c) => c.slug).join(', '),
          targetIds: n.targets.map((t) => t.id).join(', '),
        },
        { emitEvent: false },
      );
    });

    // Seed topbar synchronously; effect rehydrates on non-null note.
    this.topbar.set({
      title: 'Note editor',
      crumbs: ['Knowledge', 'Notes'],
    });
    effect(() => this.topbar.set(this.buildTopbarContext()));

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  private buildTopbarContext() {
    const n = this.note();
    const formInvalid = this.formStatus() === 'INVALID';
    const actioning = this.isActioning();

    const actions: TopbarAction[] = [
      {
        id: 'cancel',
        label: 'Cancel',
        kind: 'secondary',
        run: () => this.cancel(),
      },
      {
        id: 'save',
        label: 'Save',
        kind: 'primary',
        shortcutHint: '⌘S',
        disabled: !n || actioning || formInvalid,
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
      title: n ? `Editing · ${n.kind}` : 'Note editor',
      crumbs: n
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
    const n = this.note();
    if (!n || this.form.invalid || this._isActioning()) return;

    const v = this.form.getRawValue();
    const body: NoteUpdateRequest = {
      title: v.title.trim(),
      body: v.body,
      kind: v.kind,
      concept_slugs: splitCsv(v.conceptSlugs),
      target_ids: splitCsv(v.targetIds),
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
    if (status === 404 || status === 405 || status === 501) {
      this.notifications.info(
        `Endpoint not yet available in backend (${name}).`,
      );
      return;
    }
    this.notifications.error(`Failed to ${name.replace('-', ' ')}.`);
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

function splitCsv(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
