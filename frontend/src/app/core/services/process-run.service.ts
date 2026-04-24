import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ProcessRunKind,
  ProcessRunStatus,
  ProcessRunsResponse,
} from '../models/process-run.model';

export interface ProcessRunsQuery {
  kind?: ProcessRunKind;
  subsystem?: string;
  status?: ProcessRunStatus;
  since?: string;
}

/** Pipeline summary + stage aggregates + runs table + failures. */
@Injectable({ providedIn: 'root' })
export class ProcessRunService {
  private readonly api = inject(ApiService);

  list(query: ProcessRunsQuery = {}): Observable<ProcessRunsResponse> {
    const params: Record<string, string> = {};
    if (query.kind) params['kind'] = query.kind;
    if (query.subsystem) params['subsystem'] = query.subsystem;
    if (query.status) params['status'] = query.status;
    if (query.since) params['since'] = query.since;
    return this.api.getData<ProcessRunsResponse>(
      '/api/admin/coordination/process-runs',
      params,
    );
  }
}
