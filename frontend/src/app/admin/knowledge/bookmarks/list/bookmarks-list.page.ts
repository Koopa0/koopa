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
import { DatePipe } from '@angular/common';
import { BookmarkService } from '../../../../core/services/bookmark.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  BookmarkDetail,
  TopicRef,
} from '../../../../core/models/workbench.model';
import type { ApiListResponse } from '../../../../core/models/api.model';

type ChannelFilter = 'all' | 'rss' | 'manual' | 'shared';
type VisibilityFilter = 'all' | 'public' | 'private';

const CHANNEL_CHIPS: readonly ChannelFilter[] = [
  'all',
  'rss',
  'manual',
  'shared',
];

const VISIBILITY_CHIPS: readonly VisibilityFilter[] = [
  'all',
  'public',
  'private',
];

/**
 * Bookmarks List (list shell). Backed by
 * the admin list endpoint which includes private rows and the `actor`
 * column. Row click opens the source URL in a new tab; hosts / tags
 * are displayed as metadata columns.
 *
 * No side panel edit yet — the PUT endpoint is not live; a dedicated
 * edit route will land once the backend ships it.
 */
@Component({
  selector: 'app-bookmarks-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './bookmarks-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class BookmarksListPageComponent {
  private readonly bookmarkService = inject(BookmarkService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly channelChips = CHANNEL_CHIPS;
  protected readonly visibilityChips = VISIBILITY_CHIPS;

  protected readonly channelFilter = signal<ChannelFilter>('all');
  protected readonly visibilityFilter = signal<VisibilityFilter>('all');

  protected readonly resource = rxResource<
    ApiListResponse<BookmarkDetail>,
    void
  >({
    stream: () => this.bookmarkService.adminList({ perPage: 100 }),
  });

  protected readonly allRows = computed(
    () => this.resource.value()?.data ?? [],
  );

  protected readonly rows = computed(() => {
    const channel = this.channelFilter();
    const visibility = this.visibilityFilter();
    return this.allRows()
      .filter((b) => channel === 'all' || b.capture_channel === channel)
      .filter((b) => {
        if (visibility === 'all') return true;
        if (visibility === 'public') return b.is_public;
        return !b.is_public;
      });
  });

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
      title: 'Bookmarks',
      crumbs: ['Knowledge', 'Bookmarks'],
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

  protected setChannel(value: ChannelFilter): void {
    this.channelFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected setVisibility(value: VisibilityFilter): void {
    this.visibilityFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: BookmarkDetail): void {
    // Bookmarks are external resources — opening the URL is the
    // primary intent. A modifier-click (middle button, cmd-click) in
    // the template targets a fresh tab natively.
    if (typeof window !== 'undefined') {
      window.open(row.url, '_blank', 'noopener,noreferrer');
    }
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected topicLabel(topics: TopicRef[] | undefined): string {
    return topics?.[0]?.name ?? '—';
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
