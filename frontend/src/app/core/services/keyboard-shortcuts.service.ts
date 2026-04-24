import {
  DestroyRef,
  Injectable,
  PLATFORM_ID,
  inject,
  signal,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { fromEvent } from 'rxjs';

const A11Y_STORAGE_KEY = 'koopa:a11y-mode';
const ANNOUNCER_ID = 'koopa-announcer';
const GO_PREFIX_TIMEOUT_MS = 1200;

/** A single navigation target bound to a `G <letter>` chord. */
export interface GoToEntry {
  key: string;
  label: string;
  path: string;
}

/** Fixed `G <letter>` navigation chords for the admin shell. */
const GO_TO_REGISTRY: readonly GoToEntry[] = [
  { key: 'h', label: 'Today', path: '/admin/commitment/today' },
  { key: 't', label: 'Todos', path: '/admin/commitment/todos' },
  { key: 'g', label: 'Goals & projects', path: '/admin/commitment/goals' },
  { key: 'c', label: 'Content', path: '/admin/knowledge/content' },
  { key: 'r', label: 'Review queue', path: '/admin/knowledge/review-queue' },
  { key: 'n', label: 'Notes', path: '/admin/knowledge/notes' },
  { key: 'b', label: 'Bookmarks', path: '/admin/knowledge/bookmarks' },
  { key: 'f', label: 'Feeds', path: '/admin/knowledge/feeds' },
  { key: 'l', label: 'Learning dashboard', path: '/admin/learning' },
  { key: 'p', label: 'Concepts', path: '/admin/learning/concepts' },
  { key: 'y', label: 'Hypotheses', path: '/admin/learning/hypotheses' },
  { key: 'k', label: 'Tasks', path: '/admin/coordination/tasks' },
  { key: 'a', label: 'Activity', path: '/admin/coordination/activity' },
] as const;

/**
 * Global keyboard handler for the admin shell and public site.
 *
 * Shortcuts:
 *   • Global:  ⌘K opens the command palette · ⌘/ opens shortcut help
 *   • Nav:     `G` then a letter — G H Today, G T Todos, see GO_TO_REGISTRY
 *   • Public:  `Shift+A` quick admin entry · Shift+G scroll to bottom
 *
 * Per-page contextual shortcuts (list `j/k/Enter`, editor `⌘S`) live on
 * the host page via host metadata — they are not global because they
 * only make sense in context.
 *
 * WCAG 2.1.4: every plain single-character shortcut respects `a11yMode`.
 * Modifier-bearing shortcuts (⌘K, ⌘/, Shift+A) bypass the a11y gate.
 */
@Injectable({ providedIn: 'root' })
export class KeyboardShortcutsService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);
  private readonly router = inject(Router);
  private isInitialized = false;

  private readonly _a11yMode = signal<boolean>(this.readA11yMode());
  readonly a11yMode = this._a11yMode.asReadonly();

  private readonly _shortcutHelpOpen = signal(false);
  readonly shortcutHelpOpen = this._shortcutHelpOpen.asReadonly();

  private goPrefixActive = false;
  private goPrefixTimer: ReturnType<typeof setTimeout> | null = null;

  readonly goToRegistry: readonly GoToEntry[] = GO_TO_REGISTRY;

  init(): void {
    if (!isPlatformBrowser(this.platformId) || this.isInitialized) {
      return;
    }
    this.isInitialized = true;

    fromEvent<KeyboardEvent>(document, 'keydown')
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((event) => this.handleKeydown(event));
  }

  openShortcutHelp(): void {
    this._shortcutHelpOpen.set(true);
  }

  closeShortcutHelp(): void {
    this._shortcutHelpOpen.set(false);
  }

  toggleA11yMode(): void {
    const next = !this._a11yMode();
    this._a11yMode.set(next);
    if (isPlatformBrowser(this.platformId)) {
      try {
        localStorage.setItem(A11Y_STORAGE_KEY, next ? 'true' : 'false');
      } catch {
        // private browsing may throw — ignore.
      }
    }
    this.announce(
      next
        ? 'Accessibility mode enabled, single-character shortcuts disabled'
        : 'Accessibility mode disabled, single-character shortcuts enabled',
    );
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (this.isFormControl(event.target)) return;

    const isCmdOrCtrl = event.metaKey || event.ctrlKey;
    const isPlainKey =
      !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey;

    // ⌘K is owned by `CommandPaletteComponent`'s own host
    // `(document:keydown)` binding — don't double-dispatch here.

    // ⌘/ — shortcut help (bypasses a11y gate).
    if (isCmdOrCtrl && event.key === '/' && !event.shiftKey && !event.altKey) {
      event.preventDefault();
      this.openShortcutHelp();
      return;
    }

    // Shift+A — quick admin entry (bypasses a11y gate).
    if (
      event.shiftKey &&
      event.key === 'A' &&
      !event.metaKey &&
      !event.ctrlKey
    ) {
      event.preventDefault();
      this.router.navigate(['/admin']);
      return;
    }

    // Shift+G — scroll to bottom (public-site vim, bypasses a11y gate).
    if (
      event.shiftKey &&
      event.key === 'G' &&
      !event.metaKey &&
      !event.ctrlKey
    ) {
      window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
      return;
    }

    // Single-character shortcuts below are gated by a11y mode.
    if (isPlainKey && this._a11yMode()) return;

    if (!isPlainKey) return;

    const inAdmin = this.router.url.startsWith('/admin');

    if (inAdmin) {
      // G-prefix admin navigation chord.
      if (event.key === 'g' || event.key === 'G') {
        event.preventDefault();
        this.armGoPrefix();
        return;
      }

      if (this.goPrefixActive) {
        const target = GO_TO_REGISTRY.find(
          (e) => e.key === event.key.toLowerCase(),
        );
        this.disarmGoPrefix();
        if (target) {
          event.preventDefault();
          this.router.navigate([target.path]);
          this.announce(`Go to ${target.label}`);
        }
        return;
      }
    }

    // Public-site vim scroll (won't fire inside admin due to earlier branches).
    if (event.key === 'j') {
      window.scrollBy({ top: 100, behavior: 'smooth' });
    } else if (event.key === 'k') {
      window.scrollBy({ top: -100, behavior: 'smooth' });
    }
  }

  private armGoPrefix(): void {
    this.goPrefixActive = true;
    if (this.goPrefixTimer) clearTimeout(this.goPrefixTimer);
    this.goPrefixTimer = setTimeout(
      () => this.disarmGoPrefix(),
      GO_PREFIX_TIMEOUT_MS,
    );
  }

  private disarmGoPrefix(): void {
    this.goPrefixActive = false;
    if (this.goPrefixTimer) {
      clearTimeout(this.goPrefixTimer);
      this.goPrefixTimer = null;
    }
  }

  private announce(message: string): void {
    if (!isPlatformBrowser(this.platformId)) return;
    const el = document.getElementById(ANNOUNCER_ID);
    if (el) el.textContent = message;
  }

  private isFormControl(target: EventTarget | null): boolean {
    if (!(target instanceof HTMLElement)) return false;
    return (
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement ||
      target.isContentEditable
    );
  }

  private readA11yMode(): boolean {
    if (!isPlatformBrowser(this.platformId)) return false;
    try {
      return localStorage.getItem(A11Y_STORAGE_KEY) === 'true';
    } catch {
      return false;
    }
  }
}
