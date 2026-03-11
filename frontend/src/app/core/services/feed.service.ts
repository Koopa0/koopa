import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiFeed,
  ApiCreateFeedRequest,
  ApiUpdateFeedRequest,
  ApiResponse,
} from '../models';

@Injectable({ providedIn: 'root' })
export class FeedService {
  private readonly api = inject(ApiService);

  getFeeds(schedule?: string): Observable<ApiResponse<ApiFeed[]>> {
    const params: Record<string, string> = {};
    if (schedule) {
      params['schedule'] = schedule;
    }
    return this.api.get<ApiFeed[]>('/api/admin/feeds', params);
  }

  createFeed(body: ApiCreateFeedRequest): Observable<ApiFeed> {
    return this.api.postData<ApiFeed>('/api/admin/feeds', body);
  }

  updateFeed(id: string, body: ApiUpdateFeedRequest): Observable<ApiFeed> {
    return this.api.putData<ApiFeed>(`/api/admin/feeds/${id}`, body);
  }

  deleteFeed(id: string): Observable<void> {
    return this.api.delete(`/api/admin/feeds/${id}`);
  }

  fetchFeed(id: string): Observable<ApiResponse<{ new_items: number }>> {
    return this.api.post<{ new_items: number }>(`/api/admin/feeds/${id}/fetch`, {});
  }
}
