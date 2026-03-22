import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiTask, ApiCreateTaskRequest, ApiUpdateTaskRequest, ApiDailySummary } from '../models';

/** Admin service for tasks (Notion synced) */
@Injectable({ providedIn: 'root' })
export class TaskService {
  private readonly api = inject(ApiService);

  list(): Observable<ApiTask[]> {
    return this.api.getData<ApiTask[]>('/api/admin/tasks');
  }

  listPending(): Observable<ApiTask[]> {
    return this.api.getData<ApiTask[]>('/api/admin/tasks/pending');
  }

  create(req: ApiCreateTaskRequest): Observable<Record<string, unknown>> {
    return this.api.postData<Record<string, unknown>>('/api/admin/tasks', req);
  }

  update(id: string, req: ApiUpdateTaskRequest): Observable<Record<string, unknown>> {
    return this.api.putData<Record<string, unknown>>(`/api/admin/tasks/${id}`, req);
  }

  complete(id: string): Observable<Record<string, unknown>> {
    return this.api.postData<Record<string, unknown>>(`/api/admin/tasks/${id}/complete`, {});
  }

  batchMyDay(taskIds: string[], clear = false): Observable<Record<string, unknown>> {
    return this.api.postData<Record<string, unknown>>('/api/admin/tasks/batch-my-day', {
      task_ids: taskIds,
      clear,
    });
  }

  dailySummary(): Observable<ApiDailySummary> {
    return this.api.getData<ApiDailySummary>('/api/admin/today/summary');
  }
}
