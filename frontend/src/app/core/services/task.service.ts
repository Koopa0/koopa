import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiTask } from '../models';

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
}
