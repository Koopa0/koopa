import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
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
import { A11yModule } from '@angular/cdk/a11y';
import { Router } from '@angular/router';
import { Subject, debounceTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { trigger, transition, style, animate } from '@angular/animations';
import { NotificationService } from '../../core/services/notification.service';
import { SearchService } from '../../core/services/search.service';
import { TodoService } from '../../core/services/todo.service';
import {
  CommandPaletteService,
  type CommandAction,
} from './command-palette.service';
import type { ApiContent } from '../../core/models';
import { contentTypeRoute } from '../../core/models';

interface GroupedAction {
  name: string;
  items: (CommandAction & { flatIndex: number })[];
}

@Component({
  selector: 'app-command-palette',
  imports: [A11yModule],
  templateUrl: './command-palette.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [
    trigger('fadeBackdrop', [
      transition(':enter', [
        style({ opacity: 0 }),
        animate('150ms ease-out', style({ opacity: 1 })),
      ]),
      transition(':leave', [animate('100ms ease-in', style({ opacity: 0 }))]),
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
  private readonly todoService = inject(TodoService);
  private readonly notifications = inject(NotificationService);
  private readonly router = inject(Router);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);

  private readonly searchInput =
    viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly resultsList =
    viewChild<ElementRef<HTMLDivElement>>('resultsList');

  private readonly searchSubject = new Subject<string>();

  protected readonly isOpen = this.paletteService.isOpen;
  protected readonly query = signal('');

  /** Public visitors get the kit's writing-search prompt; admin keeps the navigate hint. */
  protected readonly searchPlaceholder = computed(() =>
    this.paletteService.isAuthenticated()
      ? 'Search content or quick navigate...'
      : 'Search writing…',
  );

  /** Whether the user is typing a search query (vs browsing actions) */
  protected readonly isSearchMode = computed(() => {
    const q = this.query().trim();
    return q.length >= 2;
  });

  /** Filter static actions by query */
  protected readonly filteredActions = computed(() => {
    const q = this.query().toLowerCase().trim();
    const actions = this.paletteService.actions();

    if (!q) {
      return actions;
    }

    // Any query — single or multi character — filters nav actions by
    // label/group/keywords. In search mode these matching commands sit above
    // the content results, so "proj" surfaces the Projects command instead of
    // collapsing straight to the GTD capture fallback.
    return actions.filter((a) => {
      const haystack = [a.label, a.group, ...(a.keywords ?? [])]
        .join(' ')
        .toLowerCase();
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

    return Array.from(groups.entries()).map(([name, items]) => ({
      name,
      items,
    }));
  });

  protected readonly searchResults = this.searchService.results;
  protected readonly isSearching = this.searchService.searching;

  /** Total selectable items count */
  protected readonly totalItems = computed(
    () => this.filteredActions().length + this.searchResults().length,
  );

  /** Active highlight index — resets to 0 when items change */
  protected readonly activeIndex = linkedSignal(() => {
    this.totalItems();
    return 0;
  });

  private readonly _isCapturing = signal(false);
  protected readonly isCapturing = this._isCapturing.asReadonly();

  /**
   * GTD capture fallback (design spec 03 §0): the query is more than one
   * character, matched no command and no entity, and the session can
   * write to the admin API. Enter then captures the raw text to the GTD
   * inbox instead of doing nothing.
   */
  protected readonly captureAvailable = computed(
    () =>
      this.paletteService.isAuthenticated() &&
      this.query().trim().length > 1 &&
      this.totalItems() === 0 &&
      !this.isSearching(),
  );

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
          document.documentElement.classList.add('overflow-hidden');
        }
      } else {
        if (isPlatformBrowser(this.platformId)) {
          document.documentElement.classList.remove('overflow-hidden');
        }
      }
    });

    // Scroll active item into view
    effect(() => {
      const idx = this.activeIndex();
      const list = this.resultsList()?.nativeElement;
      if (!list) return;

      const item = list.querySelector(
        `[data-index="${idx}"]`,
      ) as HTMLElement | null;
      if (item && typeof item.scrollIntoView === 'function') {
        item.scrollIntoView({ block: 'nearest' });
      }
    });
  }

  protected onGlobalKeydown(event: KeyboardEvent): void {
    // ⌘K / Ctrl+K to toggle. Matches the topbar's ⌘K launcher hint and
    //
    if (
      (event.metaKey || event.ctrlKey) &&
      event.key === 'k' &&
      !event.shiftKey &&
      !event.altKey
    ) {
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
    const prefix = contentTypeRoute(result.type);
    this.close();
    this.router.navigate([`${prefix}/${result.slug}`]);
  }

  protected navigateToSearch(): void {
    const q = this.query().trim();
    this.close();
    this.router.navigate(['/search'], { queryParams: q ? { q } : {} });
  }

  /** Result meta line: `{type} · {topic} · {n} min`, skipping absent parts. */
  protected getResultSubtitle(result: ApiContent): string {
    const parts = [
      result.type as string,
      result.topics[0]?.name,
      `${result.reading_time_min} min`,
    ].filter((part): part is string => Boolean(part));
    return parts.join(' · ');
  }

  /**
   * Create an inbox todo from the raw query (state=inbox — capture, not
   * clarify), toast the result, and close the palette on success. On
   * failure the palette stays open so the text is not lost.
   */
  protected captureToInbox(): void {
    const title = this.query().trim();
    if (!title || this._isCapturing()) return;

    this._isCapturing.set(true);
    this.todoService
      .create({ title, state: 'inbox' })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this._isCapturing.set(false);
          this.notifications.success(`Captured to inbox: "${title}"`);
          this.close();
        },
        error: () => {
          this._isCapturing.set(false);
          this.notifications.error('Could not capture the todo. Try again.');
        },
      });
  }

  private selectActive(): void {
    const idx = this.activeIndex();
    const actions = this.filteredActions();

    if (this.totalItems() === 0) {
      if (this.captureAvailable()) {
        this.captureToInbox();
      }
      return;
    }

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
