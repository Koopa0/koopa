import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  FeedEntryFeedback,
  FeedEntryRow,
  FeedEntryStatus,
  FeedRow,
} from '../models/feed.model';

export interface FeedEntriesQuery {
  status?: FeedEntryStatus;
  feed_id?: string;
  topic_slug?: string;
  min_relevance?: number;
  sort?: 'relevance' | 'collected_at';
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

  fetchNow(id: string): Observable<{ status: string }> {
    return this.api.postData<{ status: string }>(
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
    if (query.feed_id) params['feed_id'] = query.feed_id;
    if (query.topic_slug) params['topic_slug'] = query.topic_slug;
    if (query.min_relevance !== undefined)
      params['min_relevance'] = query.min_relevance;
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
