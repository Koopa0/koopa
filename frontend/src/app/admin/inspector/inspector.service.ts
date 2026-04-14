import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import type { InspectorTarget } from './inspector.types';

/**
 * Cross-cutting state for the Inspector right panel. URL is the source of
 * truth: `open()` updates the `?inspect=type:id` query param and a layout
 * level effect calls `syncFromUrl()` to propagate the change back into the
 * target signal. This keeps share-links and back-button behavior consistent
 * without circular updates.
 *
 * Mounted at layout level (sibling of `<router-outlet>`) so it survives
 * mode switches.
 */
@Injectable({ providedIn: 'root' })
export class InspectorService {
  private readonly router = inject(Router);

  private readonly _target = signal<InspectorTarget | null>(null);
  readonly target = this._target.asReadonly();
  readonly isOpen = computed(() => this._target() !== null);

  /**
   * Trigger inspector open by updating the URL. The layout-level URL
   * watcher will propagate this back into the target signal via
   * `syncFromUrl`.
   */
  open(target: InspectorTarget): void {
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

  /**
   * Apply a raw `?inspect=` value to the target signal. Called by the
   * layout-level URL effect. Invalid or unknown values reset the target
   * to null rather than throwing — share links to removed entity types
   * should degrade gracefully.
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
    if (type === 'goal' || type === 'project') {
      return { type, id };
    }
    return null;
  }
}
