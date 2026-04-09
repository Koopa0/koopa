import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { SystemHealth } from '../models/admin.model';

/** System health service — infrastructure monitoring API */
@Injectable({ providedIn: 'root' })
export class SystemService {
  private readonly api = inject(ApiService);

  /** Get system health status: feeds, pipeline, AI budget, database */
  getHealth(): Observable<SystemHealth> {
    return this.api.getData<SystemHealth>('/api/admin/system/health');
  }
}
