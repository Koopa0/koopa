import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  FeedEntryRow,
  FeedEntryStatus,
  FeedRow,
} from '../models/feed.model';

/**
 * Query params the backend feed-entries List handler honors. Per
 * internal/feed/entry/handler.go:32-40 the handler reads only status and
 * pagination — feed_id / topic_slug / min_relevance are not wired
 * server-side, so they are omitted here rather than sent and dropped.
 * No sort param: the backend default orders newest-first
 * (COALESCE(published_at, collected_at) DESC), which is what triage wants.
 */
export interface FeedEntriesQuery {
  status?: FeedEntryStatus;
  page?: number;
  perPage?: number;
}

/** Feed service — feeds health list + feed_entries triage. */
@Injectable({ providedIn: 'root' })
export class FeedService {
  private readonly api = inject(ApiService);

  // === Feeds ===

  listFeeds(): Observable<FeedRow[]> {
    return this.api.getData<FeedRow[]>('/api/admin/knowledge/feeds');
  }

  fetchNow(id: string): Observable<{ new_items: number }> {
    return this.api.postData<{ new_items: number }>(
      `/api/admin/knowledge/feeds/${id}/fetch`,
      {},
    );
  }

  updateFeed(
    id: string,
    body: Partial<Pick<FeedRow, 'enabled' | 'schedule'>>,
  ): Observable<FeedRow> {
    return this.api.putData<FeedRow>(`/api/admin/knowledge/feeds/${id}`, body);
  }

  // === Feed entries / triage ===

  listEntries(query: FeedEntriesQuery = {}): Observable<FeedEntryRow[]> {
    const params: Record<string, string | number> = {};
    if (query.status) params['status'] = query.status;
    if (query.page) params['page'] = query.page;
    if (query.perPage) params['per_page'] = query.perPage;
    return this.api.getData<FeedEntryRow[]>(
      '/api/admin/knowledge/feed-entries',
      params,
    );
  }

  curate(entryId: string, contentId: string): Observable<void> {
    return this.api.postData<void>(
      `/api/admin/knowledge/feed-entries/${entryId}/curate`,
      { content_id: contentId },
    );
  }

  ignore(entryId: string): Observable<void> {
    return this.api.postData<void>(
      `/api/admin/knowledge/feed-entries/${entryId}/ignore`,
      {},
    );
  }
}
