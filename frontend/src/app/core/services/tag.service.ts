import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent } from '../models';

export interface TagInfo {
  name: string;
  count: number;
}

/** Tag is not a standalone API — aggregated from content list tags field */
@Injectable({ providedIn: 'root' })
export class TagService {
  private readonly content = inject(ContentService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  /** Get content list by tag */
  getContentsByTag(
    tag: string,
    page = 1,
    perPage = 20,
  ): Observable<{ contents: ApiContent[]; meta: { total: number; page: number; per_page: number; total_pages: number } }> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.listPublished({ tag, page, perPage }).pipe(
      map((res) => ({ contents: res.data, meta: res.meta })),
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('Failed to load tag content');
        return throwError(() => err);
      }),
    );
  }
}
