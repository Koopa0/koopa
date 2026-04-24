import { Injectable, inject } from '@angular/core';
import { type Observable, forkJoin, map } from 'rxjs';
import { ApiService } from './api.service';
import type {
  Artifact,
  CoordinationTask,
  TaskMessage,
} from '../models/workbench.model';

export interface SubmitTaskRequest {
  title: string;
  description?: string;
  target: string;
  parts?: { text: string }[];
}

@Injectable({ providedIn: 'root' })
export class TaskService {
  private readonly api = inject(ApiService);

  open(): Observable<CoordinationTask[]> {
    return this.api.getData<CoordinationTask[]>(
      '/api/admin/coordination/tasks/open',
    );
  }

  completed(): Observable<CoordinationTask[]> {
    return this.api.getData<CoordinationTask[]>(
      '/api/admin/coordination/tasks/completed',
    );
  }

  /**
   * Union of open + completed. Mirrors what the spec's unified
   * `GET /api/admin/coordination/tasks?state=...` will expose once
   * the backend consolidates the two paths.
   */
  listAll(): Observable<CoordinationTask[]> {
    return forkJoin({
      open: this.open(),
      completed: this.completed(),
    }).pipe(map(({ open, completed }) => [...open, ...completed]));
  }

  get(id: string): Observable<CoordinationTask> {
    return this.api.getData<CoordinationTask>(
      `/api/admin/coordination/tasks/${id}`,
    );
  }

  messages(taskId: string): Observable<TaskMessage[]> {
    return this.api.getData<TaskMessage[]>(
      `/api/admin/coordination/tasks/${taskId}/messages`,
    );
  }

  artifacts(taskId: string): Observable<Artifact[]> {
    return this.api.getData<Artifact[]>(
      `/api/admin/coordination/tasks/${taskId}/artifacts`,
    );
  }

  reply(taskId: string, text: string): Observable<TaskMessage> {
    return this.api.postData<TaskMessage>(
      `/api/admin/coordination/tasks/${taskId}/reply`,
      {
        parts: [{ text }],
      },
    );
  }

  requestRevision(
    taskId: string,
    reason?: string,
  ): Observable<CoordinationTask> {
    return this.api.postData<CoordinationTask>(
      `/api/admin/coordination/tasks/${taskId}/request-revision`,
      reason ? { reason } : {},
    );
  }

  /** Human-only acknowledge of a completed task. */
  approve(taskId: string, notes?: string): Observable<CoordinationTask> {
    return this.api.postData<CoordinationTask>(
      `/api/admin/coordination/tasks/${taskId}/approve`,
      notes ? { notes } : {},
    );
  }

  /** Cancels a submitted or working task. */
  cancel(taskId: string, reason?: string): Observable<CoordinationTask> {
    return this.api.postData<CoordinationTask>(
      `/api/admin/coordination/tasks/${taskId}/cancel`,
      reason ? { reason } : {},
    );
  }

  /** Human submits a new task. */
  submit(body: SubmitTaskRequest): Observable<CoordinationTask> {
    return this.api.postData<CoordinationTask>(
      '/api/admin/coordination/tasks',
      body,
    );
  }
}
