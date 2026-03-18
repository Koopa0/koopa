import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiStatsOverview,
  ApiDriftReport,
  ApiLearningDashboard,
} from '../models';

/** Admin service for dashboard stats */
@Injectable({ providedIn: 'root' })
export class StatsService {
  private readonly api = inject(ApiService);

  getOverview(): Observable<ApiStatsOverview> {
    return this.api.getData<ApiStatsOverview>('/api/admin/stats');
  }

  getDrift(days = 30): Observable<ApiDriftReport> {
    return this.api.getData<ApiDriftReport>('/api/admin/stats/drift', { days });
  }

  getLearning(): Observable<ApiLearningDashboard> {
    return this.api.getData<ApiLearningDashboard>('/api/admin/stats/learning');
  }
}
