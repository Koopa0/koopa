import { Injectable, signal } from '@angular/core';

/** A discrete chip on the topbar page-action row. */
export interface TopbarAction {
  /** Stable id, used as `data-testid` and for `track`. */
  id: string;
  label: string;
  /** Primary = filled button; secondary = ghost button; destructive = red ghost. */
  kind?: 'primary' | 'secondary' | 'destructive';
  disabled?: boolean;
  /** Optional keyboard hint shown on the right (`⌘S`, etc.). Display only. */
  shortcutHint?: string;
  /** Invoked on click. Host page owns the handler. */
  run: () => void;
}

export interface TopbarContext {
  title: string;
  crumbs?: string[];
  /** Primary buttons rendered in-line on the topbar. Keep ≤ 4. */
  actions?: TopbarAction[];
  /** Secondary actions surfaced inside the `…` overflow menu. */
  overflowActions?: TopbarAction[];
}

const DEFAULT_CONTEXT: TopbarContext = {
  title: '',
  crumbs: [],
  actions: [],
  overflowActions: [],
};

/**
 * Publishes the topbar context (title / crumbs / page actions) that
 * {@link AdminTopbarComponent} renders. Pages populate this in their
 * constructor so the shell stays OnPush without ViewChild queries or
 * route-data juggling.
 *
 * Ownership: whoever calls `set()` most recently wins. On navigation
 * away the host page MUST call `reset()` via `DestroyRef` so leaking
 * context does not cross routes.
 */
@Injectable({ providedIn: 'root' })
export class AdminTopbarService {
  private readonly _context = signal<TopbarContext>(DEFAULT_CONTEXT);
  readonly context = this._context.asReadonly();

  set(ctx: TopbarContext): void {
    this._context.set({
      title: ctx.title,
      crumbs: ctx.crumbs ?? [],
      actions: ctx.actions ?? [],
      overflowActions: ctx.overflowActions ?? [],
    });
  }

  reset(): void {
    this._context.set(DEFAULT_CONTEXT);
  }
}
