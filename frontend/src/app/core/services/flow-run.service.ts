import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiFlowRun,
  ApiListResponse,
  FlowRunStatus,
} from '../models';

export interface FlowRunFilters {
  page?: number;
  perPage?: number;
  status?: FlowRunStatus;
  flowName?: string;
}

@Injectable({ providedIn: 'root' })
export class FlowRunService {
  private readonly api = inject(ApiService);

  getFlowRuns(filters: FlowRunFilters = {}): Observable<ApiListResponse<ApiFlowRun>> {
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
    if (filters.flowName) {
      params['flow_name'] = filters.flowName;
    }

    return this.api.getListData<ApiFlowRun>('/api/admin/flow-runs', params);
  }

  getFlowRun(id: string): Observable<ApiFlowRun> {
    return this.api.getData<ApiFlowRun>(`/api/admin/flow-runs/${id}`);
  }

  retryFlowRun(id: string): Observable<unknown> {
    return this.api.post(`/api/admin/flow-runs/${id}/retry`, {});
  }
}
