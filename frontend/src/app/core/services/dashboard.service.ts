import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { ApiService } from './api.service';
import type { DashboardTrends } from '../models/admin.model';

/** 趨勢儀表板服務 — 系統方向性指標 */
@Injectable({ providedIn: 'root' })
export class DashboardService {
  private readonly api = inject(ApiService);

  getDashboardTrends(): Observable<DashboardTrends> {
    // TODO: return this.api.getData<DashboardTrends>('/api/admin/dashboard/trends');
    return of(MOCK_DASHBOARD_TRENDS);
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_DASHBOARD_TRENDS: DashboardTrends = {
  period: '2026-04-01 ~ 2026-04-07',
  execution: {
    tasks_completed_this_week: 11,
    tasks_completed_last_week: 8,
    trend: 'up',
  },
  plan_adherence: {
    completion_rate_this_week: 73,
    completion_rate_last_week: 65,
  },
  goal_health: {
    on_track: 2,
    at_risk: 1,
    stalled: 1,
  },
  learning: {
    sessions_this_week: 4,
    weakness_count: 6,
    weakness_change: -2,
    mastery_count: 14,
    mastery_change: 3,
    review_backlog: 8,
  },
  content: {
    published_this_month: 3,
    published_target: 12,
    drafts_in_progress: 2,
  },
  inbox_health: {
    current_count: 5,
    week_start_count: 9,
    clarified_this_week: 7,
    captured_this_week: 3,
  },
  someday_health: {
    total: 12,
    stale_count: 3,
  },
  directive_health: {
    open_count: 2,
    avg_resolution_days: 4.5,
  },
};
