import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { Agent } from '../models/workbench.model';

/**
 * Agent service — read-only registry projection.
 *
 * Backend: internal/agent/handler.go. `List` (GET /api/admin/system/agents)
 * returns a bare []agentResponse; `Get` (GET /api/admin/system/agents/{name})
 * returns a single agentResponse. Each row is the six-field identity
 * projection — name, display_name, platform, description, optional schedule,
 * status. There are no task counts or capability flags.
 */
@Injectable({ providedIn: 'root' })
export class AgentService {
  private readonly api = inject(ApiService);

  list(): Observable<Agent[]> {
    return this.api.getData<Agent[]>('/api/admin/system/agents');
  }

  get(name: string): Observable<Agent> {
    return this.api.getData<Agent>(`/api/admin/system/agents/${name}`);
  }
}
