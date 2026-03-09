import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  effect,
  ElementRef,
  viewChild,
  linkedSignal,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { Subject, debounceTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  trigger,
  transition,
  style,
  animate,
} from '@angular/animations';
import { SearchService } from '../../core/services/search.service';
import {
  CommandPaletteService,
  type CommandAction,
} from './command-palette.service';
import type { ApiContent, ContentType } from '../../core/models';

interface GroupedAction {
  name: string;
  items: (CommandAction & { flatIndex: number })[];
}

const CONTENT_TYPE_LABELS: Record<ContentType, string> = {
  article: '文章',
  essay: '隨筆',
  'build-log': '日誌',
  til: 'TIL',
  note: '筆記',
  bookmark: '書籤',
  digest: '摘要',
};

const TYPE_ROUTE_MAP: Record<ContentType, string> = {
  article: '/articles',
  essay: '/essays',
  'build-log': '/build-logs',
  til: '/til',
  note: '/notes',
  bookmark: '/bookmarks',
  digest: '/digests',
};

@Component({
  selector: 'app-command-palette',
  standalone: true,
  templateUrl: './command-palette.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [
    trigger('fadeBackdrop', [
      transition(':enter', [
        style({ opacity: 0 }),
        animate('150ms ease-out', style({ opacity: 1 })),
      ]),
      transition(':leave', [
        animate('100ms ease-in', style({ opacity: 0 })),
      ]),
    ]),
    trigger('scaleIn', [
      transition(':enter', [
        style({ opacity: 0, transform: 'scale(0.95) translateY(-8px)' }),
        animate(
          '150ms ease-out',
          style({ opacity: 1, transform: 'scale(1) translateY(0)' }),
        ),
      ]),
      transition(':leave', [
        animate(
          '100ms ease-in',
          style({ opacity: 0, transform: 'scale(0.95) translateY(-8px)' }),
        ),
      ]),
    ]),
  ],
  host: {
    '(document:keydown)': 'onGlobalKeydown($event)',
  },
})
export class CommandPaletteComponent {
  private readonly paletteService = inject(CommandPaletteService);
  private readonly searchService = inject(SearchService);
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);

  private readonly searchInput = viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly resultsList = viewChild<ElementRef<HTMLDivElement>>('resultsList');

  private readonly searchSubject = new Subject<string>();

  protected readonly isOpen = this.paletteService.isOpen;
  protected readonly query = signal('');
  protected readonly searchPlaceholder = '搜尋內容或快速導航...';

  /** Whether the user is typing a search query (vs browsing actions) */
  protected readonly isSearchMode = computed(() => {
    const q = this.query().trim();
    return q.length >= 2;
  });

  /** Filter static actions by query */
  protected readonly filteredActions = computed(() => {
    const q = this.query().toLowerCase().trim();
    const actions = this.paletteService.actions();

    if (!q || this.isSearchMode()) {
      return this.isSearchMode() ? [] : actions;
    }

    // Single character — still show actions, filtered
    return actions.filter((a) => {
      const haystack = [a.label, a.group, ...(a.keywords ?? [])].join(' ').toLowerCase();
      return haystack.includes(q);
    });
  });

  /** Group actions by their group name, with flat indices for keyboard nav */
  protected readonly groupedActions = computed<GroupedAction[]>(() => {
    const actions = this.filteredActions();
    const groups = new Map<string, (CommandAction & { flatIndex: number })[]>();
    let idx = 0;

    for (const action of actions) {
      const items = groups.get(action.group) ?? [];
      items.push({ ...action, flatIndex: idx++ });
      groups.set(action.group, items);
    }

    return Array.from(groups.entries()).map(([name, items]) => ({ name, items }));
  });

  protected readonly searchResults = this.searchService.results;
  protected readonly isSearching = this.searchService.searching;

  /** Total selectable items count */
  private readonly totalItems = computed(() =>
    this.filteredActions().length + this.searchResults().length,
  );

  /** Active highlight index — resets to 0 when items change */
  protected readonly activeIndex = linkedSignal(() => {
    this.totalItems();
    return 0;
  });

  constructor() {
    // Debounced search
    this.searchSubject
      .pipe(debounceTime(300), takeUntilDestroyed())
      .subscribe((q) => {
        if (q.trim().length >= 2) {
          this.searchService.search(q);
        } else {
          this.searchService.clearSearch();
        }
      });

    // Auto-focus input when opened
    effect(() => {
      if (this.isOpen()) {
        // Defer to next tick so the DOM is rendered
        setTimeout(() => this.searchInput()?.nativeElement.focus(), 0);

        // Lock body scroll
        if (isPlatformBrowser(this.platformId)) {
          document.body.style.overflow = 'hidden';
        }
      } else {
        if (isPlatformBrowser(this.platformId)) {
          document.body.style.overflow = '';
        }
      }
    });

    // Scroll active item into view
    effect(() => {
      const idx = this.activeIndex();
      const list = this.resultsList()?.nativeElement;
      if (!list) return;

      const item = list.querySelector(`[data-index="${idx}"]`) as HTMLElement | null;
      if (item && typeof item.scrollIntoView === 'function') {
        item.scrollIntoView({ block: 'nearest' });
      }
    });
  }

  protected onGlobalKeydown(event: KeyboardEvent): void {
    // ⌘K / Ctrl+K to toggle
    if (event.key === 'k' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      if (this.isOpen()) {
        this.close();
      } else {
        this.paletteService.open();
      }
    }
  }

  protected onInput(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.query.set(value);
    this.searchSubject.next(value);
  }

  protected onKeydown(event: KeyboardEvent): void {
    const total = this.totalItems();

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.activeIndex.set((this.activeIndex() + 1) % Math.max(total, 1));
        break;

      case 'ArrowUp':
        event.preventDefault();
        this.activeIndex.set(
          (this.activeIndex() - 1 + Math.max(total, 1)) % Math.max(total, 1),
        );
        break;

      case 'Enter':
        event.preventDefault();
        this.selectActive();
        break;

      case 'Escape':
        event.preventDefault();
        this.close();
        break;
    }
  }

  protected close(): void {
    this.query.set('');
    this.searchService.clearSearch();
    this.paletteService.close();
  }

  protected executeAction(action: CommandAction['action']): void {
    this.close();
    action();
  }

  protected selectSearchResult(result: ApiContent): void {
    const prefix = TYPE_ROUTE_MAP[result.type] ?? '/articles';
    this.close();
    this.router.navigate([`${prefix}/${result.slug}`]);
  }

  protected getTypeLabel(type: ContentType): string {
    return CONTENT_TYPE_LABELS[type] ?? type;
  }

  private selectActive(): void {
    const idx = this.activeIndex();
    const actions = this.filteredActions();

    if (idx < actions.length) {
      this.executeAction(actions[idx].action);
    } else {
      const searchIdx = idx - actions.length;
      const results = this.searchResults();
      if (searchIdx < results.length) {
        this.selectSearchResult(results[searchIdx]);
      }
    }
  }
}
