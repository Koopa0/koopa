import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  FeedEntryFeedback,
  FeedEntryRow,
  FeedEntryStatus,
  FeedRow,
} from '../models/feed.model';

/**
 * Query params the backend feed-entries List handler honors. Per
 * internal/feed/entry/handler.go:32-40 the handler reads only status,
 * sort (the literal "relevance" enables relevance ordering), and
 * pagination — feed_id / topic_slug / min_relevance are not wired
 * server-side, so they are omitted here rather than sent and dropped.
 */
export interface FeedEntriesQuery {
  status?: FeedEntryStatus;
  sort?: 'relevance';
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
    body: Partial<Pick<FeedRow, 'enabled' | 'schedule' | 'priority'>>,
  ): Observable<FeedRow> {
    return this.api.putData<FeedRow>(`/api/admin/knowledge/feeds/${id}`, body);
  }

  // === Feed entries / triage ===

  listEntries(query: FeedEntriesQuery = {}): Observable<FeedEntryRow[]> {
    const params: Record<string, string | number> = {};
    if (query.status) params['status'] = query.status;
    if (query.sort) params['sort'] = query.sort;
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

  feedback(entryId: string, feedback: FeedEntryFeedback): Observable<void> {
    return this.api.postData<void>(
      `/api/admin/knowledge/feed-entries/${entryId}/feedback`,
      { feedback },
    );
  }
}
