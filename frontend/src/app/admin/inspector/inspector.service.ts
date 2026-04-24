import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import type { InspectorTargetType } from '../../core/models/workbench.model';
import type { InspectorAction, InspectorTarget } from './inspector.types';

/** Valid inspector target types for URL parsing. */
const VALID_TYPES: ReadonlySet<string> = new Set<InspectorTargetType>([
  'content',
  'hypothesis',
  'task',
  'goal',
  'project',
  'todo',
  'concept',
  'agent',
  'bookmark',
]);

/**
 * Cross-cutting state for the Inspector right panel.
 *
 * URL is the source of truth: `open()` updates `?inspect=type:id` and the
 * layout-level effect calls `syncFromUrl()` to propagate back into the
 * target signal. This keeps share-links and back-button consistent.
 *
 * Renderer-driven tabs: the shell reads tab definitions from the active
 * renderer. The `activeTab` signal is managed here so the shell tab bar
 * can bind to it, but tab definitions come from each renderer component.
 *
 * Auto-advance: after an endorsement action, the queue component watches
 * `lastAction` and calls `open(nextItem)` to advance. Atlas does not
 * set up this watcher, so auto-advance is structural, not flag-based.
 */
@Injectable({ providedIn: 'root' })
export class InspectorService {
  private readonly router = inject(Router);

  private readonly _target = signal<InspectorTarget | null>(null);
  readonly target = this._target.asReadonly();
  readonly isOpen = computed(() => this._target() !== null);

  /** Active tab ID within the current inspector renderer. */
  private readonly _activeTab = signal<string>('');
  readonly activeTab = this._activeTab.asReadonly();

  /**
   * Last endorsement action performed. Queue component watches this
   * to auto-advance. The timestamp ensures the effect fires even if
   * the same type+id is acted upon twice.
   */
  private readonly _lastAction = signal<InspectorAction | null>(null);
  readonly lastAction = this._lastAction.asReadonly();

  /** Open the inspector by updating the URL query param. */
  open(target: InspectorTarget): void {
    this._activeTab.set('');
    this.router.navigate([], {
      queryParams: { inspect: `${target.type}:${target.id}` },
      queryParamsHandling: 'merge',
    });
  }

  /** Close the inspector by clearing the query param. */
  close(): void {
    this.router.navigate([], {
      queryParams: { inspect: null },
      queryParamsHandling: 'merge',
    });
  }

  /** Set the active tab (called by renderer or tab bar). */
  setActiveTab(tabId: string): void {
    this._activeTab.set(tabId);
  }

  /**
   * Record an endorsement action. Called by renderer action bars
   * after a successful API call (publish, reject, verify, etc.).
   * Queue component watches this to auto-advance.
   */
  recordAction(type: InspectorTargetType, id: string, action: string): void {
    this._lastAction.set({ type, id, action, timestamp: Date.now() });
  }

  /**
   * Apply a raw `?inspect=` value to the target signal. Called by the
   * layout-level URL effect. Invalid or unknown values reset to null
   * rather than throwing — share links to removed entity types degrade
   * gracefully.
   */
  syncFromUrl(raw: string | null | undefined): void {
    this._target.set(this.parseTarget(raw));
  }

  private parseTarget(raw: string | null | undefined): InspectorTarget | null {
    if (!raw) return null;
    const colonIdx = raw.indexOf(':');
    if (colonIdx === -1) return null;
    const type = raw.substring(0, colonIdx);
    const id = raw.substring(colonIdx + 1);
    if (!id) return null;
    if (VALID_TYPES.has(type)) {
      return { type: type as InspectorTargetType, id };
    }
    return null;
  }
}
