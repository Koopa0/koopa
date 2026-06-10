import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  DriftReport,
  StatsLearning,
  StatsOverview,
  SystemHealth,
} from '../models/admin.model';

/** System health + stats service — infrastructure monitoring API */
@Injectable({ providedIn: 'root' })
export class SystemService {
  private readonly api = inject(ApiService);

  /** Get system health status: feeds, pipeline, database */
  getHealth(): Observable<SystemHealth> {
    return this.api.getData<SystemHealth>('/api/admin/system/health');
  }

  /** Get inventory aggregates: contents, collected, feeds, runs, activity */
  getStats(): Observable<StatsOverview> {
    return this.api.getData<StatsOverview>('/api/admin/system/stats');
  }

  /** Get the area drift report (goal share vs activity share) */
  getDrift(days?: number): Observable<DriftReport> {
    return this.api.getData<DriftReport>(
      '/api/admin/system/stats/drift',
      days === undefined ? undefined : { days },
    );
  }

  /** Get learning content stats: note growth, weekly cadence, top tags */
  getLearningStats(): Observable<StatsLearning> {
    return this.api.getData<StatsLearning>('/api/admin/system/stats/learning');
  }
}
