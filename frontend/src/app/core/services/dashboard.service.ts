import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { DashboardTrends } from '../models/admin.model';

/** Trend dashboard service — system directional metrics */
@Injectable({ providedIn: 'root' })
export class DashboardService {
  private readonly api = inject(ApiService);

  getDashboardTrends(): Observable<DashboardTrends> {
    return this.api.getData<DashboardTrends>('/api/admin/dashboard/trends');
  }
}
