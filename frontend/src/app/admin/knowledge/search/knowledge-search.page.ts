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
import {
  rxResource,
  toObservable,
  toSignal,
} from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { debounceTime, distinctUntilChanged } from 'rxjs';
import {
  SearchService,
  type AdminSearchKind,
  type AdminSearchResult,
} from '../../../core/services/search.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

const DEBOUNCE_MS = 250;
const RESULT_LIMIT = 30;

/** Per-kind row presentation: dot color + jump target. */
const KIND_DOT: Record<AdminSearchKind, string> = {
  content: 'bg-(--dot-article)',
  note: 'bg-(--dot-note)',
};

const KIND_ROUTE: Record<AdminSearchKind, string[]> = {
  content: ['/admin/knowledge/content'],
  note: ['/admin/knowledge/notes'],
};

/**
 * Admin global search over GET /api/admin/search (content + note
 * sources, merged server-side). Typing re-queries after a debounce;
 * a row click jumps to the entity's editor route.
 *
 * Keyboard: j/k move row focus, Enter opens the focused row.
 */
@Component({
  selector: 'app-knowledge-search-page',
  standalone: true,
  templateUrl: './knowledge-search.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class KnowledgeSearchPageComponent {
  private readonly searchService = inject(SearchService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly query = signal('');

  private readonly debouncedQuery = toSignal(
    toObservable(this.query).pipe(
      debounceTime(DEBOUNCE_MS),
      distinctUntilChanged(),
    ),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<
    AdminSearchResult[],
    string | undefined
  >({
    params: () => this.debouncedQuery().trim() || undefined,
    stream: ({ params }) => this.searchService.adminSearch(params, RESULT_LIMIT),
  });

  protected readonly rows = computed(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );
  protected readonly total = computed(() => this.rows().length);
  protected readonly isIdle = computed(() => this.query().trim() === '');
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly isEmpty = computed(
    () =>
      !this.isIdle() &&
      !this.isLoading() &&
      !this.hasError() &&
      this.rows().length === 0,
  );

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLButtonElement>>('row');

  constructor() {
    this.topbar.set({ title: 'Search', crumbs: ['Knowledge', 'Search'] });

    effect(() => {
      const idx = this.focusedIndex();
      const target = this.rowRefs()[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: AdminSearchResult): void {
    void this.router.navigate([...KIND_ROUTE[row.type], row.id, 'edit']);
  }

  protected dotClass(kind: AdminSearchKind): string {
    return KIND_DOT[kind];
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
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
