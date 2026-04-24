import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  AgentsResponse,
  AgentDetail,
  AgentTasksResponse,
} from '../models/workbench.model';

/** agent_note row surfaced on the agent profile. */
export interface AgentNoteRow {
  id: string;
  kind: 'plan' | 'context' | 'reflection';
  body_md: string;
  metadata: Record<string, unknown>;
  created_at: string;
  actor: string;
}

export interface AgentNotesQuery {
  /** Comma-separated kinds; pass an array and the service joins. */
  kind?: ('plan' | 'context' | 'reflection')[];
  since?: string;
  until?: string;
}

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

  /** Agent's task history split into assignee / creator / artifacts. */
  tasks(name: string): Observable<AgentTasksResponse> {
    return this.api.getData<AgentTasksResponse>(
      `/api/admin/coordination/agents/${name}/tasks`,
    );
  }

  /** agent_notes stream for the Context notes tab. */
  notes(name: string, query: AgentNotesQuery = {}): Observable<AgentNoteRow[]> {
    const params: Record<string, string> = {};
    if (query.kind?.length) params['kind'] = query.kind.join(',');
    if (query.since) params['since'] = query.since;
    if (query.until) params['until'] = query.until;
    return this.api.getData<AgentNoteRow[]>(
      `/api/admin/coordination/agents/${name}/notes`,
      params,
    );
  }
}
