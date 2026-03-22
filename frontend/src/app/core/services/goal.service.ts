import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiGoal, GoalStatus } from '../models';

/** Admin service for goals (Notion synced) */
@Injectable({ providedIn: 'root' })
export class GoalService {
  private readonly api = inject(ApiService);

  list(): Observable<ApiGoal[]> {
    return this.api.getData<ApiGoal[]>('/api/admin/goals');
  }

  updateStatus(id: string, status: GoalStatus): Observable<Record<string, unknown>> {
    return this.api.putData<Record<string, unknown>>(`/api/admin/goals/${id}/status`, { status });
  }
}
