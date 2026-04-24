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
import { HttpErrorResponse } from '@angular/common/http';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  ConceptKind,
  ConceptRow,
  MasteryStage,
} from '../../../../core/models/learning.model';

type KindFilter = 'all' | ConceptKind;
type StageFilter = 'all' | MasteryStage;

interface Chip<T extends string> {
  value: T;
  label: string;
}

const KIND_CHIPS: readonly Chip<KindFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'pattern', label: 'Pattern' },
  { value: 'skill', label: 'Skill' },
  { value: 'principle', label: 'Principle' },
];

const STAGE_CHIPS: readonly Chip<StageFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'struggling', label: 'Struggling' },
  { value: 'developing', label: 'Developing' },
  { value: 'solid', label: 'Solid' },
];

const STAGE_TEXT: Record<MasteryStage, string> = {
  struggling: 'text-red-300',
  developing: 'text-sky-300',
  solid: 'text-emerald-300',
};

const STAGE_DOT: Record<MasteryStage, string> = {
  struggling: 'bg-red-500',
  developing: 'bg-sky-400',
  solid: 'bg-emerald-500',
};

/**
 * Concepts list .
 *
 * Columns: Slug / Kind / Domain / Mastery / Counts / Next due.
 * Row click → concept profile route.
 */
@Component({
  selector: 'app-concepts-list-page',
  standalone: true,
  imports: [DataTableComponent],
  templateUrl: './concepts-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class ConceptsListPageComponent {
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly kindChips = KIND_CHIPS;
  protected readonly stageChips = STAGE_CHIPS;

  protected readonly kindFilter = signal<KindFilter>('all');
  protected readonly stageFilter = signal<StageFilter>('all');

  protected readonly resource = rxResource<
    ConceptRow[],
    { kind: KindFilter; stage: StageFilter }
  >({
    params: () => ({ kind: this.kindFilter(), stage: this.stageFilter() }),
    stream: ({ params }) =>
      this.learningService.concepts({
        kind: params.kind === 'all' ? undefined : params.kind,
        mastery_stage: params.stage === 'all' ? undefined : params.stage,
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
      title: 'Concepts',
      crumbs: ['Learning', 'Concepts'],
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

  protected setStageFilter(value: StageFilter): void {
    this.stageFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: ConceptRow): void {
    this.router.navigate(['/admin/learning/concepts', row.slug]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected stageText(s: MasteryStage): string {
    return STAGE_TEXT[s];
  }
  protected stageDot(s: MasteryStage): string {
    return STAGE_DOT[s];
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
