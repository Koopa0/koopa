import { Injectable } from '@angular/core';
import { Observable, of } from 'rxjs';
import type { SystemHealth } from '../models/admin.model';

/** 系統健康服務 — 基礎設施監控 API */
@Injectable({ providedIn: 'root' })
export class SystemService {
  /** 取得系統健康狀態：feeds、pipeline、AI 預算、資料庫 */
  getHealth(): Observable<SystemHealth> {
    // TODO: replace with real API when backend implements
    // return this.api.getData<SystemHealth>('/api/admin/system/health');
    return of(MOCK_HEALTH);
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位須嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_HEALTH: SystemHealth = {
  feeds: {
    total: 15,
    healthy: 13,
    failing: 2,
    failing_feeds: [
      {
        name: 'Hacker News Best',
        error: 'Connection timeout after 30s',
        since: '2026-04-07T14:22:00Z',
      },
      {
        name: 'Go Weekly Newsletter',
        error: 'HTTP 403 Forbidden — possible rate limit',
        since: '2026-04-06T09:15:00Z',
      },
    ],
  },
  pipelines: {
    recent_runs: 10,
    failed: 0,
    last_run_at: '2026-04-08T06:30:00Z',
  },
  ai_budget: {
    today_tokens: 45000,
    daily_limit: 100000,
  },
  database: {
    contents_count: 142,
    tasks_count: 67,
    notes_count: 320,
  },
};
