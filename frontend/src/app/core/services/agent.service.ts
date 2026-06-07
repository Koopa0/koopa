import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  AgentsResponse,
  AgentDetail,
} from '../models/workbench.model';

/**
 * Agent service — registry list + per-agent open/blocked task counts for the
 * AGENTS cell.
 *
 * Backend: internal/agent/handler.go::List (route GET /api/admin/coordination/agents) +
 * task store batch counts. The cell warns when any
 * agent.activity_state === 'blocked' and surfaces one word per agent
 * (active / idle / blocked).
 */
@Injectable({ providedIn: 'root' })
export class AgentService {
  private readonly api = inject(ApiService);

  list(): Observable<AgentsResponse> {
    return this.api.getData<AgentsResponse>('/api/admin/coordination/agents');
  }

  /**
   * Single-agent detail for Agent Inspector.
   * Returns AgentDetail (extends AgentSummary with retired_at, schedule_human_readable,
   * last_task_accepted_at — see workbench.model.ts).
   */
  get(name: string): Observable<AgentDetail> {
    return this.api.getData<AgentDetail>(
      `/api/admin/coordination/agents/${name}`,
    );
  }
}
