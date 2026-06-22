import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  untracked,
  viewChildren,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Data, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { map } from 'rxjs';
import { ContentService } from '../../../../core/services/content.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import {
  CONTENT_TYPE_CONFIG,
  type ApiContent,
  type ApiListResponse,
  type ContentStatus,
  type ContentType,
} from '../../../../core/models';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';

type TypeFilter = 'all' | ContentType;
type StatusFilter = 'all' | ContentStatus;

/** Shape the router may pass on `data:` for this route. */
export interface ContentListRouteData extends Data {
  title?: string;
  crumbs?: string[];
  initialStatus?: StatusFilter;
}

const EMPTY_ROUTE_DATA: ContentListRouteData = {};

interface TypeChip {
  value: TypeFilter;
  label: string;
}

interface StatusChip {
  value: StatusFilter;
  label: string;
}

const TYPE_CHIPS: readonly TypeChip[] = [
  { value: 'all', label: 'All' },
  { value: 'article', label: 'Article' },
  { value: 'essay', label: 'Essay' },
  { value: 'build-log', label: 'Build Log' },
  { value: 'til', label: 'TIL' },
  { value: 'digest', label: 'Digest' },
];

const STATUS_CHIPS: readonly StatusChip[] = [
  { value: 'all', label: 'All' },
  { value: 'draft', label: 'Draft' },
  { value: 'review', label: 'Review' },
  { value: 'published', label: 'Published' },
  { value: 'archived', label: 'Archived' },
];

const STATUS_DOT_CLASS: Record<ContentStatus, string> = {
  draft: 'bg-fg-subtle',
  review: 'bg-warn',
  published: 'bg-success',
  archived: 'bg-fg-faint',
};

const STATUS_TEXT_CLASS: Record<ContentStatus, string> = {
  draft: 'text-fg-muted',
  review: 'text-warn',
  published: 'text-success',
  archived: 'text-fg-subtle',
};

/**
 * Content List — powers both `/admin/knowledge/content` and
 * `/admin/knowledge/review-queue`. The two differ only in the default
 * status filter and the page title, both resolved from route data.
 *
 * Columns: Title / Type / Topic / Actor / Status / Public / Updated / ID.
 * `actor` shows the proposing agent (`created_by`) for content pushed via the
 * MCP propose_content tool, and `—` for owner/admin-authored content. The
 * review queue (initialStatus='review') is the primary consumer: a proposed
 * row also renders "Proposed by {agent}" and its rationale under the title.
 *
 * Keyboard:
 *   j / k   — move row focus down / up (roving tabindex)
 *   Enter   — open the focused row in the editor
 *
 * Page-scoped keyboard binding uses `host:` metadata rather than a
 * global registry — these shortcuts only make sense while this page
 * is mounted.
 */
@Component({
  selector: 'app-content-list-page',
  imports: [DataTableComponent, DatePipe],
  templateUrl: './content-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class ContentListPageComponent {
  private readonly contentService = inject(ContentService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly typeChips = TYPE_CHIPS;
  protected readonly statusChips = STATUS_CHIPS;

  private readonly routeData = toSignal(
    this.route.data.pipe(map((d): ContentListRouteData => d)),
    { initialValue: EMPTY_ROUTE_DATA },
  );

  private readonly defaultStatusFilter = computed<StatusFilter>(
    () => this.routeData().initialStatus ?? 'all',
  );

  protected readonly typeFilter = signal<TypeFilter>('all');
  protected readonly statusFilter = signal<StatusFilter>('all');

  protected readonly resource = rxResource<
    ApiListResponse<ApiContent>,
    { type: TypeFilter; status: StatusFilter }
  >({
    params: () => ({
      type: this.typeFilter(),
      status: this.statusFilter(),
    }),
    stream: ({ params }) =>
      this.contentService.adminList({
        type: params.type === 'all' ? undefined : params.type,
        status: params.status === 'all' ? undefined : params.status,
        perPage: 100,
      }),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives
  // the error banner; without this guard a failed list read throws here.
  // The value is an envelope, so guard the source then read `.data`/`.meta`.
  protected readonly rows = computed(() =>
    this.resource.hasValue() ? this.resource.value().data : [],
  );
  protected readonly total = computed(() => {
    if (!this.resource.hasValue()) return 0;
    const value = this.resource.value();
    return value.meta.total ?? value.data.length ?? 0;
  });
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

  /** Roving-tabindex target: only this row is reachable via Tab. */
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    // Keep topbar + default status filter in sync with route data. An
    // effect instead of a one-shot keeps this correct if Angular ever
    // reuses the component across sibling routes.
    effect(() => {
      const data = this.routeData();
      this.topbar.set({
        title: data.title ?? 'All content',
        crumbs: data.crumbs ?? ['Knowledge', 'Content'],
        actions: [
          {
            id: 'new-content',
            label: 'New',
            kind: 'primary',
            run: () => {
              void this.router.navigate(['/admin/knowledge/content/new']);
            },
          },
        ],
      });
    });
    effect(() => {
      const next = this.defaultStatusFilter();
      untracked(() => this.statusFilter.set(next));
    });

    // Roving focus: when focusedIndex changes, move DOM focus to the
    // corresponding row so keyboard semantics match the visual state.
    effect(() => {
      const idx = this.focusedIndex();
      const refs = this.rowRefs();
      const target = refs[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setTypeFilter(value: TypeFilter): void {
    this.typeFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected setStatusFilter(value: StatusFilter): void {
    this.statusFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: ApiContent): void {
    this.router.navigate(['/admin/knowledge/content', row.id, 'edit']);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected typeBadgeClass(type: ContentType): string {
    return (
      CONTENT_TYPE_CONFIG[type]?.badgeClasses ??
      'border-border-strong bg-elevated text-fg-muted'
    );
  }

  protected typeLabel(type: ContentType): string {
    return CONTENT_TYPE_CONFIG[type]?.label ?? type;
  }

  protected statusDotClass(status: ContentStatus): string {
    return STATUS_DOT_CLASS[status];
  }

  protected statusTextClass(status: ContentStatus): string {
    return STATUS_TEXT_CLASS[status];
  }

  protected topicLabel(row: ApiContent): string {
    return row.topics?.[0]?.name ?? '—';
  }

  /** The proposing agent, when this row was pushed via propose_content. */
  protected proposer(row: ApiContent): string | null {
    return row.created_by ?? null;
  }

  /** The proposing agent's rationale, when present. */
  protected rationale(row: ApiContent): string | null {
    return row.proposal_rationale ?? null;
  }

  /**
   * Host-level keydown handler. Only `j` and `k` are bound here; Enter
   * is owned by the per-row `(keydown.enter)` binding so focus-tracking
   * and activation stay coupled.
   */
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
