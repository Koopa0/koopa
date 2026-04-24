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
import { HypothesisService } from '../../../../core/services/hypothesis.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  Hypothesis,
  HypothesisState,
} from '../../../../core/models/workbench.model';

type StateFilter = 'all' | HypothesisState;

interface StateChip {
  value: StateFilter;
  label: string;
}

const STATE_CHIPS: readonly StateChip[] = [
  { value: 'all', label: 'All' },
  { value: 'unverified', label: 'Unverified' },
  { value: 'verified', label: 'Verified' },
  { value: 'invalidated', label: 'Invalidated' },
  { value: 'archived', label: 'Archived' },
];

const STATE_DOT_CLASS: Record<HypothesisState, string> = {
  unverified: 'bg-amber-400',
  verified: 'bg-emerald-500',
  invalidated: 'bg-red-500',
  archived: 'bg-zinc-600',
};

const STATE_TEXT_CLASS: Record<HypothesisState, string> = {
  unverified: 'text-amber-300',
  verified: 'text-emerald-300',
  invalidated: 'text-red-300',
  archived: 'text-zinc-500',
};

/**
 * Hypotheses List — Learning domain entry. `GET /api/admin/learning/hypotheses`
 * supports server-side `state=` filtering; we pass the signal-driven
 * filter through to the query so no client-side join is needed.
 *
 * Columns: Claim / State / Created by / Observed / Created / ID.
 */
@Component({
  selector: 'app-hypotheses-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './hypotheses-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class HypothesesListPageComponent {
  private readonly hypothesisService = inject(HypothesisService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly stateChips = STATE_CHIPS;
  protected readonly stateFilter = signal<StateFilter>('unverified');

  protected readonly resource = rxResource<Hypothesis[], StateFilter>({
    params: () => this.stateFilter(),
    stream: ({ params }) =>
      this.hypothesisService.list(params === 'all' ? undefined : params),
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

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    this.topbar.set({
      title: 'Hypotheses',
      crumbs: ['Learning', 'Hypotheses'],
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

  protected setStateFilter(value: StateFilter): void {
    this.stateFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: Hypothesis): void {
    this.router.navigate(['/admin/learning/hypotheses', row.id]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected stateDotClass(state: HypothesisState): string {
    return STATE_DOT_CLASS[state];
  }

  protected stateTextClass(state: HypothesisState): string {
    return STATE_TEXT_CLASS[state];
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
