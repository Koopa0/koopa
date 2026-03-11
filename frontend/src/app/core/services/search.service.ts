import { Injectable, inject, signal, computed } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

@Injectable({ providedIn: 'root' })
export class SearchService {
  private readonly content = inject(ContentService);

  private readonly _query = signal('');
  private readonly _results = signal<ApiContent[]>([]);
  private readonly _meta = signal<ApiPaginationMeta | null>(null);
  private readonly _searching = signal(false);

  readonly query = this._query.asReadonly();
  readonly results = this._results.asReadonly();
  readonly meta = this._meta.asReadonly();
  readonly searching = this._searching.asReadonly();
  readonly hasResults = computed(() => this._results().length > 0);

  /** Full-text search — calls backend /api/search */
  search(query: string, page = 1, perPage = 20): void {
    this._query.set(query);

    if (!query.trim()) {
      this._results.set([]);
      this._meta.set(null);
      return;
    }

    this._searching.set(true);

    this.content
      .search(query, { page, perPage })
      .pipe(
        catchError((err) => {
          this._searching.set(false);
          return throwError(() => err);
        }),
      )
      .subscribe((res) => {
        this._results.set(res.data);
        this._meta.set(res.meta);
        this._searching.set(false);
      });
  }

  clearSearch(): void {
    this._query.set('');
    this._results.set([]);
    this._meta.set(null);
  }
}
