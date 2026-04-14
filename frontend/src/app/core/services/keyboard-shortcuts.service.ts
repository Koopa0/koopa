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

/**
 * Global keyboard handler. Single source for both the public-site vim
 * scroll bindings and the admin shell's mode-switching shortcuts.
 *
 * WCAG 2.1.4 compliance: every plain (no-modifier) shortcut respects
 * the `a11yMode` toggle — when enabled, all single-character shortcuts
 * are disabled so screen-reader users with browse-mode key passthrough
 * regain full keyboard control. The toggle persists in `localStorage`.
 *
 * Modifier-bearing shortcuts (e.g. ⌘/) bypass the a11y gate because they
 * cannot be triggered accidentally by assistive tech key passthrough.
 */
@Injectable({
  providedIn: 'root',
})
export class KeyboardShortcutsService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);
  private readonly router = inject(Router);
  private isInitialized = false;

  private readonly _a11yMode = signal<boolean>(this.readA11yMode());
  readonly a11yMode = this._a11yMode.asReadonly();

  init(): void {
    if (!isPlatformBrowser(this.platformId) || this.isInitialized) {
      return;
    }
    this.isInitialized = true;

    fromEvent<KeyboardEvent>(document, 'keydown')
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((event) => this.handleKeydown(event));
  }

  toggleA11yMode(): void {
    const next = !this._a11yMode();
    this._a11yMode.set(next);
    if (isPlatformBrowser(this.platformId)) {
      try {
        localStorage.setItem(A11Y_STORAGE_KEY, next ? 'true' : 'false');
      } catch {
        // localStorage may throw in private browsing — ignore.
      }
    }
    this.announce(
      next
        ? 'Accessibility mode enabled, single-character shortcuts disabled'
        : 'Accessibility mode disabled, single-character shortcuts enabled',
    );
  }

  /**
   * Write to a global aria-live="polite" region that the root component
   * mounts at startup. Avoids pulling in @angular/cdk/a11y (~15 kB) for
   * the only feature we actually use from it.
   */
  private announce(message: string): void {
    if (!isPlatformBrowser(this.platformId)) return;
    const el = document.getElementById(ANNOUNCER_ID);
    if (el) {
      el.textContent = message;
    }
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (this.isFormControl(event.target)) {
      return;
    }

    const isPlainKey =
      !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey;

    // Plain single-char shortcuts are gated by a11y mode for WCAG 2.1.4.
    // Shifted/modifier shortcuts (Shift+A, ⌘/) bypass the gate.
    if (isPlainKey && this._a11yMode()) {
      return;
    }

    // Shift+A — quick admin entry from anywhere.
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

    // Shift+G — scroll to bottom of page (vim-like).
    if (
      event.shiftKey &&
      event.key === 'G' &&
      !event.metaKey &&
      !event.ctrlKey
    ) {
      window.scrollTo({
        top: document.body.scrollHeight,
        behavior: 'smooth',
      });
      return;
    }

    // Admin-only mode switching
    const inAdmin = this.router.url.startsWith('/admin');
    if (inAdmin && isPlainKey) {
      if (event.key === '1') {
        event.preventDefault();
        this.router.navigate(['/admin/now']);
        this.announce('NOW mode');
        return;
      }
      if (event.key === '2') {
        event.preventDefault();
        this.router.navigate(['/admin/atlas']);
        this.announce('ATLAS mode');
        return;
      }
    }

    // Public-site vim scroll shortcuts (work everywhere when not in
    // a form control). Will be overridden by per-component handlers
    // when admin list navigation lands.
    if (isPlainKey) {
      if (event.key === 'j') {
        window.scrollBy({ top: 100, behavior: 'smooth' });
      } else if (event.key === 'k') {
        window.scrollBy({ top: -100, behavior: 'smooth' });
      }
    }
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
