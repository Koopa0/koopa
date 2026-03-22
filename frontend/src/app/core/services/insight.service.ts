import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiInsightsResponse, ApiUpdateInsightRequest, InsightStatus } from '../models';

/** Admin service for insights (session note subtype) */
@Injectable({ providedIn: 'root' })
export class InsightService {
  private readonly api = inject(ApiService);

  list(params?: { status?: InsightStatus | 'all'; project?: string; limit?: number }): Observable<ApiInsightsResponse> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.project) searchParams.set('project', params.project);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    const qs = searchParams.toString();
    return this.api.getData<ApiInsightsResponse>('/api/admin/insights' + (qs ? '?' + qs : ''));
  }

  update(id: number, req: ApiUpdateInsightRequest): Observable<Record<string, unknown>> {
    return this.api.putData<Record<string, unknown>>(`/api/admin/insights/${id}`, req);
  }
}
