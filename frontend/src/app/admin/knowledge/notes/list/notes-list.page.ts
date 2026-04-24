import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChildren,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  NoteService,
  type NoteRow,
} from '../../../../core/services/note.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type { NoteKind, NoteMaturity } from '../../../../core/models/api.model';

type KindFilter = 'all' | NoteKind;
type MaturityFilter = 'all' | NoteMaturity;

interface Chip<T extends string> {
  value: T;
  label: string;
}

const KIND_CHIPS: readonly Chip<KindFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'solve-note', label: 'Solve' },
  { value: 'concept-note', label: 'Concept' },
  { value: 'debug-postmortem', label: 'Debug' },
  { value: 'decision-log', label: 'Decision' },
  { value: 'reading-note', label: 'Reading' },
  { value: 'musing', label: 'Musing' },
];

const MATURITY_CHIPS: readonly Chip<MaturityFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'seed', label: 'Seed' },
  { value: 'stub', label: 'Stub' },
  { value: 'evergreen', label: 'Evergreen' },
  { value: 'needs_revision', label: 'Revise' },
  { value: 'archived', label: 'Archived' },
];

const MATURITY_DOT: Record<NoteMaturity, string> = {
  seed: 'bg-zinc-400',
  stub: 'bg-sky-400',
  evergreen: 'bg-emerald-500',
  needs_revision: 'bg-amber-400',
  archived: 'bg-zinc-600',
};

const MATURITY_TEXT: Record<NoteMaturity, string> = {
  seed: 'text-zinc-300',
  stub: 'text-sky-300',
  evergreen: 'text-emerald-300',
  needs_revision: 'text-amber-300',
  archived: 'text-zinc-500',
};

const KIND_SHORT: Record<NoteKind, string> = {
  'solve-note': 'solve',
  'concept-note': 'cnpt',
  'debug-postmortem': 'dbg',
  'decision-log': 'dec',
  'reading-note': 'read',
  musing: 'mus',
};

/**
 * Notes list. When the list endpoint returns 404/405/501 the page
 * renders an 'Endpoints pending' banner instead of an empty table.
 *
 * Columns: Kind / Title / Maturity / Actor / Concepts / Updated / ID.
 * Row click opens the editor.
 */
@Component({
  selector: 'app-notes-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './notes-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class NotesListPageComponent {
  private readonly noteService = inject(NoteService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly kindChips = KIND_CHIPS;
  protected readonly maturityChips = MATURITY_CHIPS;

  protected readonly kindFilter = signal<KindFilter>('all');
  protected readonly maturityFilter = signal<MaturityFilter>('all');

  protected readonly resource = rxResource<
    NoteRow[],
    { kind: KindFilter; maturity: MaturityFilter }
  >({
    params: () => ({
      kind: this.kindFilter(),
      maturity: this.maturityFilter(),
    }),
    stream: ({ params }) =>
      this.noteService.list({
        kind: params.kind === 'all' ? undefined : params.kind,
        maturity: params.maturity === 'all' ? undefined : params.maturity,
      }),
  });

  protected readonly rows = computed(() => this.resource.value() ?? []);
  protected readonly total = computed(() => this.rows().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && this.rows().length === 0,
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly endpointsUnavailable = computed(() => {
    if (this.resource.status() !== 'error') return false;
    const err = this.resource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    this.topbar.set({
      title: 'Notes',
      crumbs: ['Knowledge', 'Notes'],
    });

    effect(() => {
      const idx = this.focusedIndex();
      const target = this.rowRefs()[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setKindFilter(value: KindFilter): void {
    this.kindFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected setMaturityFilter(value: MaturityFilter): void {
    this.maturityFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: NoteRow): void {
    this.router.navigate(['/admin/knowledge/notes', row.id, 'edit']);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected kindShort(kind: NoteKind): string {
    return KIND_SHORT[kind];
  }

  protected maturityDotClass(m: NoteMaturity): string {
    return MATURITY_DOT[m];
  }

  protected maturityTextClass(m: NoteMaturity): string {
    return MATURITY_TEXT[m];
  }

  protected conceptsLabel(row: NoteRow): string {
    if (row.concepts.length === 0) return '—';
    const first = row.concepts[0].name;
    return row.concepts.length > 1
      ? `${first} +${row.concepts.length - 1}`
      : first;
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (isFormControl(event.target)) return;
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;

    const rows = this.rows();
    if (rows.length === 0) return;

    if (event.key === 'j') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.min(i + 1, rows.length - 1));
    } else if (event.key === 'k') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.max(i - 1, 0));
    }
  }
}

function isFormControl(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target.isContentEditable
  );
}
