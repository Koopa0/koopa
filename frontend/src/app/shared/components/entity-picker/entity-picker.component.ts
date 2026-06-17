import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  input,
  model,
  signal,
  viewChild,
  viewChildren,
} from '@angular/core';
import { rxResource, toObservable } from '@angular/core/rxjs-interop';
import { debounceTime, distinctUntilChanged } from 'rxjs';
import type { Observable } from 'rxjs';

/**
 * A pickable entity. `label` is the primary text, `sublabel` an optional
 * disambiguating line (e.g. a concept's domain). `id` is the stable key the
 * parent persists.
 */
export interface PickerEntity {
  id: string;
  label: string;
  sublabel?: string;
}

/** A search function the parent supplies (e.g. concept vs target search). */
export type PickerSearchFn = (query: string) => Observable<PickerEntity[]>;

const DEBOUNCE_MS = 250;

/**
 * Reusable search-select-chips picker. A debounced search input feeds a
 * results dropdown; clicking (or Enter-selecting) a result adds it as a
 * removable chip. The selected set is two-way bound via {@link selected} so a
 * parent form owns the full list.
 *
 * Generic over {@link PickerEntity} — the parent maps its domain rows into
 * `{ id, label, sublabel }` and supplies the {@link search} function.
 *
 * Keyboard: ArrowDown/ArrowUp move the active result, Enter selects it, Escape
 * clears the query, Backspace on an empty input removes the last chip.
 */
@Component({
  selector: 'app-entity-picker',
  templateUrl: './entity-picker.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EntityPickerComponent {
  /** Parent-supplied search; debounced query in, matching entities out. */
  readonly search = input.required<PickerSearchFn>();
  /** The selected set — two-way bound so the parent form owns it. */
  readonly selected = model<PickerEntity[]>([]);
  readonly placeholder = input('Search…');
  /** Accessible label for the combobox input. */
  readonly label = input('');
  /** Ties the visible <label> to the input; falls back to the selector id. */
  readonly inputId = input('entity-picker-input');

  private readonly inputRef =
    viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly optionRefs =
    viewChildren<ElementRef<HTMLButtonElement>>('option');

  protected readonly query = signal('');
  /** Active descendant index for keyboard navigation; -1 = none. */
  protected readonly activeIndex = signal(-1);

  private readonly debouncedQuery = toObservable(this.query).pipe(
    debounceTime(DEBOUNCE_MS),
    distinctUntilChanged(),
  );

  private readonly resource = rxResource<PickerEntity[], string | undefined>({
    params: () => this.query().trim() || undefined,
    stream: ({ params }) => this.search()(params),
  });

  // Guard reads with hasValue(): a failed load otherwise throws on value().
  private readonly hits = computed(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );

  /** Hits minus entities already selected — never offer a duplicate. */
  protected readonly results = computed(() => {
    const taken = new Set(this.selected().map((e) => e.id));
    return this.hits().filter((e) => !taken.has(e.id));
  });

  protected readonly isIdle = computed(() => this.query().trim() === '');
  protected readonly isLoading = computed(
    () => !this.isIdle() && this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly isEmpty = computed(
    () =>
      !this.isIdle() &&
      !this.isLoading() &&
      !this.hasError() &&
      this.results().length === 0,
  );
  /** The dropdown is shown only when there is something to show. */
  protected readonly isOpen = computed(
    () =>
      !this.isIdle() &&
      (this.isLoading() ||
        this.hasError() ||
        this.results().length > 0 ||
        this.isEmpty()),
  );

  protected readonly listboxId = computed(() => `${this.inputId()}-listbox`);

  protected activeOptionId(): string | null {
    const i = this.activeIndex();
    const r = this.results();
    return i >= 0 && i < r.length
      ? `${this.inputId()}-option-${r[i].id}`
      : null;
  }

  protected optionId(entity: PickerEntity): string {
    return `${this.inputId()}-option-${entity.id}`;
  }

  protected setQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
    this.activeIndex.set(-1);
  }

  protected add(entity: PickerEntity): void {
    if (this.selected().some((e) => e.id === entity.id)) return;
    this.selected.update((list) => [...list, entity]);
    this.query.set('');
    this.activeIndex.set(-1);
    this.inputRef()?.nativeElement.focus();
  }

  protected remove(entity: PickerEntity): void {
    this.selected.update((list) => list.filter((e) => e.id !== entity.id));
  }

  protected handleKeydown(event: KeyboardEvent): void {
    const results = this.results();

    if (event.key === 'ArrowDown') {
      if (results.length === 0) return;
      event.preventDefault();
      this.activeIndex.update((i) => Math.min(i + 1, results.length - 1));
      this.scrollActiveIntoView();
      return;
    }
    if (event.key === 'ArrowUp') {
      if (results.length === 0) return;
      event.preventDefault();
      this.activeIndex.update((i) => Math.max(i - 1, 0));
      this.scrollActiveIntoView();
      return;
    }
    if (event.key === 'Enter') {
      const i = this.activeIndex();
      if (i >= 0 && i < results.length) {
        event.preventDefault();
        this.add(results[i]);
      }
      return;
    }
    if (event.key === 'Escape') {
      if (this.query() !== '') {
        event.preventDefault();
        this.query.set('');
        this.activeIndex.set(-1);
      }
      return;
    }
    if (event.key === 'Backspace' && this.query() === '') {
      const list = this.selected();
      if (list.length > 0) {
        this.remove(list[list.length - 1]);
      }
    }
  }

  private scrollActiveIntoView(): void {
    const target = this.optionRefs()[this.activeIndex()];
    target?.nativeElement.scrollIntoView({ block: 'nearest' });
  }
}
