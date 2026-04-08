import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { ApiService } from './api.service';
import type { StudioOverview } from '../models/admin.model';

/** Studio 協調服務 — IPC 指令、報告、參與者 */
@Injectable({ providedIn: 'root' })
export class StudioService {
  private readonly api = inject(ApiService);

  getOverview(): Observable<StudioOverview> {
    // TODO: return this.api.getData<StudioOverview>('/api/admin/studio');
    return of(MOCK_STUDIO_OVERVIEW);
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_STUDIO_OVERVIEW: StudioOverview = {
  open_directives: [
    {
      id: 1,
      content:
        '研究 NATS exactly-once semantics，產出技術報告含 benchmark 結果與 Go 實作建議',
      source: 'hq',
      target: 'research-lab',
      priority: 'p1',
      lifecycle_status: 'pending',
      has_report: false,
      acknowledged_at: null,
      resolved_at: null,
      issued_date: '2026-04-05',
      created_at: '2026-04-05T10:00:00+08:00',
      days_open: 3,
    },
    {
      id: 2,
      content:
        '撰寫 Go Concurrency Patterns 系列文章第一篇，涵蓋 goroutine lifecycle 與 errgroup',
      source: 'hq',
      target: 'content-studio',
      priority: 'p0',
      lifecycle_status: 'acknowledged',
      has_report: false,
      acknowledged_at: '2026-04-04T14:30:00+08:00',
      resolved_at: null,
      issued_date: '2026-04-03',
      created_at: '2026-04-03T09:00:00+08:00',
      days_open: 5,
    },
  ],
  unread_reports: [
    {
      id: 1,
      source: 'research-lab',
      content:
        'pgvector 0.8 效能測試完成：HNSW 在 100 萬向量上 recall@10 = 0.98，查詢延遲 p99 < 5ms。建議搭配 IVFFlat 做混合索引。',
      in_response_to: null,
      directive_content: null,
      reported_date: '2026-04-07',
      created_at: '2026-04-07T18:00:00+08:00',
    },
  ],
  participants: [
    {
      name: 'hq',
      platform: 'claude-code',
      active_directives: 2,
      recent_reports: 0,
      can_issue_directives: true,
      can_receive_directives: false,
      can_write_reports: false,
      task_assignable: false,
    },
    {
      name: 'content-studio',
      platform: 'claude-ai',
      active_directives: 1,
      recent_reports: 0,
      can_issue_directives: false,
      can_receive_directives: true,
      can_write_reports: true,
      task_assignable: true,
    },
    {
      name: 'research-lab',
      platform: 'claude-ai',
      active_directives: 1,
      recent_reports: 1,
      can_issue_directives: false,
      can_receive_directives: true,
      can_write_reports: true,
      task_assignable: false,
    },
    {
      name: 'learning-studio',
      platform: 'claude-code',
      active_directives: 0,
      recent_reports: 0,
      can_issue_directives: false,
      can_receive_directives: true,
      can_write_reports: true,
      task_assignable: true,
    },
  ],
};
