import { Injectable, inject } from '@angular/core';
import { map, type Observable } from 'rxjs';
import { ApiService } from './api.service';

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
