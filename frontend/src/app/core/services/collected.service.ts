import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiCollectedItem,
  ApiListResponse,
  CollectedStatus,
  CollectedFeedback,
} from '../models';

export interface CollectedFilters {
  page?: number;
  perPage?: number;
  status?: CollectedStatus;
}

@Injectable({ providedIn: 'root' })
export class CollectedService {
  private readonly api = inject(ApiService);

  getCollected(
    filters: CollectedFilters = {},
  ): Observable<ApiListResponse<ApiCollectedItem>> {
    const params: Record<string, string | number> = {};
    if (filters.page) {
      params['page'] = filters.page;
    }
    if (filters.perPage) {
      params['per_page'] = filters.perPage;
    }
    if (filters.status) {
      params['status'] = filters.status;
    }

    return this.api.getListData<ApiCollectedItem>(
      '/api/admin/collected',
      params,
    );
  }

  sendFeedback(id: string, feedback: CollectedFeedback): Observable<void> {
    return this.api.postVoid(`/api/admin/collected/${id}/feedback`, {
      feedback,
    });
  }

  ignoreItem(id: string): Observable<void> {
    return this.api.postVoid(`/api/admin/collected/${id}/ignore`, {});
  }

  curateItem(id: string, contentId?: string): Observable<void> {
    const body: Record<string, string> = {};
    if (contentId) {
      body['content_id'] = contentId;
    }
    return this.api.postVoid(`/api/admin/collected/${id}/curate`, body);
  }
}
