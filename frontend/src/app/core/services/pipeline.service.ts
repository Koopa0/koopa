import { Injectable, inject, signal } from '@angular/core';
import { Observable, tap, catchError, throwError } from 'rxjs';
import { ApiService } from './api.service';

export type PipelineAction =
  | 'sync'
  | 'collect'
  | 'generate'
  | 'digest'
  | 'notion-sync'
  | 'reconcile'
  | 'bookmark';

@Injectable({ providedIn: 'root' })
export class PipelineService {
  private readonly api = inject(ApiService);

  private readonly _triggering = signal<PipelineAction | null>(null);
  readonly triggering = this._triggering.asReadonly();

  /** Trigger Obsidian/GitHub sync */
  triggerSync(): Observable<unknown> {
    return this.trigger('sync');
  }

  /** Trigger RSS feed collection */
  triggerCollect(): Observable<unknown> {
    return this.trigger('collect');
  }

  /** Trigger AI content generation */
  triggerGenerate(): Observable<unknown> {
    return this.trigger('generate');
  }

  /** Trigger weekly digest generation */
  triggerDigest(): Observable<unknown> {
    return this.trigger('digest');
  }

  /** Trigger Notion sync (Projects/Tasks/Books/Goals) */
  triggerNotionSync(): Observable<unknown> {
    return this.trigger('notion-sync');
  }

  /** Trigger full Obsidian + Notion reconciliation */
  triggerReconcile(): Observable<unknown> {
    return this.trigger('reconcile');
  }

  /** Trigger bookmark generation */
  triggerBookmark(): Observable<unknown> {
    return this.trigger('bookmark');
  }

  private trigger(action: PipelineAction): Observable<unknown> {
    this._triggering.set(action);
    return this.api.post(`/api/admin/pipeline/${action}`, {}).pipe(
      tap(() => this._triggering.set(null)),
      catchError((err) => {
        this._triggering.set(null);
        return throwError(() => err);
      }),
    );
  }
}
