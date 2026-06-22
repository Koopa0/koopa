import { Injectable, inject, signal, computed } from '@angular/core';
import { map, type Observable, type Subscription } from 'rxjs';
import { ApiService } from './api.service';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

/** Entity kind of an admin search hit — routes the click target. */
export type AdminSearchKind = 'content';

/** Single hit from the admin global search endpoint. */
export interface AdminSearchResult {
  type: AdminSearchKind;
  id: string;
  slug?: string;
  title: string;
  excerpt?: string;
  score: number;
}

interface AdminSearchResponse {
  results: AdminSearchResult[];
}

@Injectable({ providedIn: 'root' })
export class SearchService {
  private readonly api = inject(ApiService);
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

  private searchSub: Subscription | null = null;

  /** Full-text search — calls backend /api/search */
  search(query: string, page = 1, perPage = 20): void {
    this._query.set(query);

    if (!query.trim()) {
      this._results.set([]);
      this._meta.set(null);
      return;
    }

    this._searching.set(true);

    this.searchSub?.unsubscribe();
    this.searchSub = this.content
      .search(query, { page, perPage })
      .subscribe({
        next: (res) => {
          this._results.set(res.data);
          this._meta.set(res.meta);
          this._searching.set(false);
        },
        error: () => {
          this._searching.set(false);
        },
      });
  }

  clearSearch(): void {
    this._query.set('');
    this._results.set([]);
    this._meta.set(null);
  }

  /**
   * Admin global search — content hits from GET /api/admin/search.
   * Stateless; callers own the result signal.
   */
  adminSearch(query: string, limit = 20): Observable<AdminSearchResult[]> {
    return this.api
      .getData<AdminSearchResponse>('/api/admin/search', { q: query, limit })
      .pipe(map((res) => res.results ?? []));
  }
}
