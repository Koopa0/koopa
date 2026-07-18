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
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { trigger, transition, style, animate } from '@angular/animations';
import { NotificationService } from '../../core/services/notification.service';
import { TodoService } from '../../core/services/todo.service';
import {
  CommandPaletteService,
  type CommandAction,
} from './command-palette.service';

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
  private readonly todoService = inject(TodoService);
  private readonly notifications = inject(NotificationService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);

  private readonly searchInput =
    viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly resultsList =
    viewChild<ElementRef<HTMLDivElement>>('resultsList');

  protected readonly isOpen = this.paletteService.isOpen;
  protected readonly query = signal('');

  /** The palette filters local navigation and offers authenticated GTD capture. */
  protected readonly searchPlaceholder = computed(() =>
    this.paletteService.isAuthenticated()
      ? 'Quick navigate or capture…'
      : 'Quick navigate…',
  );

  /** Whether the user has typed enough text to show a no-match result. */
  protected readonly hasQuery = computed(() => {
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

    // Any query filters navigation by label, group, and keywords. A matching
    // command takes precedence over the GTD capture fallback.
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

  /** Total selectable items count */
  protected readonly totalItems = computed(() => this.filteredActions().length);

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
      this.totalItems() === 0,
  );

  constructor() {
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
    this.paletteService.close();
  }

  protected executeAction(action: CommandAction['action']): void {
    this.close();
    action();
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
    }
  }
}
