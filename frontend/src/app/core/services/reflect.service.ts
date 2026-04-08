import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { ApiService } from './api.service';
import type {
  DailyReflectionContext,
  WeeklyReviewContext,
  JournalEntry,
  InsightCheck,
} from '../models/admin.model';

/** 反思服務 — 每日回顧、週報、日誌、洞察 */
@Injectable({ providedIn: 'root' })
export class ReflectService {
  private readonly api = inject(ApiService);

  /** 取得每日反思 context */
  getDailyContext(_date?: string): Observable<DailyReflectionContext> {
    // TODO: return this.api.getData<DailyReflectionContext>(`/api/admin/reflect/daily${date ? `?date=${date}` : ''}`);
    return of(MOCK_DAILY_CONTEXT);
  }

  /** 取得週報 context */
  getWeeklyContext(_weekStart?: string): Observable<WeeklyReviewContext> {
    // TODO: return this.api.getData<WeeklyReviewContext>(`/api/admin/reflect/weekly${weekStart ? `?week_start=${weekStart}` : ''}`);
    return of(MOCK_WEEKLY_CONTEXT);
  }

  /** 寫入日誌條目 */
  writeJournal(_entry: JournalEntry): Observable<void> {
    // TODO: return this.api.postVoid('/api/admin/reflect/journal', entry);
    return of(undefined);
  }

  /** 取得日誌條目列表 */
  getJournalEntries(limit?: number): Observable<JournalEntry[]> {
    // TODO: return this.api.getData<JournalEntry[]>(`/api/admin/reflect/journal?limit=${limit ?? 20}`);
    const entries = limit
      ? MOCK_JOURNAL_ENTRIES.slice(0, limit)
      : MOCK_JOURNAL_ENTRIES;
    return of(entries);
  }

  /** 取得洞察列表 */
  getInsights(): Observable<InsightCheck[]> {
    // TODO: return this.api.getData<InsightCheck[]>('/api/admin/reflect/insights');
    return of(MOCK_INSIGHTS);
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_DAILY_CONTEXT: DailyReflectionContext = {
  date: '2026-04-08',
  plan_vs_actual: {
    planned: 5,
    completed: 3,
    deferred: 1,
    dropped: 1,
  },
  completed_tasks: [
    {
      id: 'task-101',
      title: 'Implement admin sidebar navigation',
      area: 'frontend',
    },
    {
      id: 'task-103',
      title: 'Review RSS pipeline error handling',
      area: 'backend',
    },
    {
      id: 'task-110',
      title: 'Write Go error handling article outline',
      area: 'learning',
    },
  ],
  learning_sessions: [
    {
      id: 'session-001',
      domain: 'algorithms',
      started_at: '2026-04-08T14:00:00+08:00',
      duration_minutes: 45,
      attempts_count: 6,
      solved_count: 4,
    },
  ],
  content_changes: [
    { title: 'Go Error Handling Patterns', type: 'article', action: 'drafted' },
    { title: 'Admin Redesign Build Log', type: 'build-log', action: 'updated' },
  ],
  commits_count: 5,
  inbox_delta: {
    captured: 3,
    clarified: 2,
    net: 1,
  },
};

const MOCK_WEEKLY_CONTEXT: WeeklyReviewContext = {
  week_start: '2026-04-01',
  week_end: '2026-04-07',
  goal_progress: [
    {
      goal_title: 'Ship koopa0.dev v1 public launch',
      milestones_completed_this_week: 1,
      total_done: 3,
      total: 5,
    },
    {
      goal_title: 'Publish 12 technical articles by Q2',
      milestones_completed_this_week: 0,
      total_done: 4,
      total: 12,
    },
  ],
  project_health: [
    {
      title: 'koopa0.dev Frontend',
      status: 'in-progress',
      tasks_completed: 4,
      stalled: false,
    },
    {
      title: 'koopa0.dev Backend',
      status: 'in-progress',
      tasks_completed: 2,
      stalled: false,
    },
    {
      title: 'Obsidian Plugin: Auto-Frontmatter',
      status: 'on-hold',
      tasks_completed: 0,
      stalled: true,
    },
  ],
  learning_summary: {
    sessions_count: 3,
    total_minutes: 135,
    concepts_improved: ['binary-search', 'dynamic-programming'],
    concepts_declined: ['graph-traversal'],
  },
  content_output: {
    published: 1,
    drafted: 2,
  },
  inbox_health: {
    start_count: 8,
    end_count: 4,
    clarified: 6,
    captured: 2,
  },
  insights_needing_check: [
    {
      id: 'insight-001',
      hypothesis: 'RSS pipeline 的 error rate 會在週末飆升，因為來源網站維護',
      status: 'unverified',
      age_days: 12,
    },
  ],
  metrics: {
    tasks_completed: 9,
    commits: 23,
    build_logs: 4,
  },
};

const MOCK_JOURNAL_ENTRIES: JournalEntry[] = [
  {
    kind: 'reflection',
    body: '決定把重心放在 admin redesign，NATS 整合延後一週。今天完成了 sidebar navigation 的實作，整體進度比預期順利。',
    date: '2026-04-08',
  },
  {
    kind: 'plan',
    body: '本週目標：完成 Reflect section 的四個頁面。優先處理 daily review 和 journal，weekly review 和 insights 可以稍後。',
    date: '2026-04-07',
  },
  {
    kind: 'context',
    body: 'GDE 申請需要在 5/25 前準備好 community contribution portfolio，目前進度 50%。需要加速 article 產出。',
    date: '2026-04-06',
  },
  {
    kind: 'metrics',
    body: '本週 commit 數：23。文章進度：4/12。LeetCode 練習：6 題。RSS 收集正常運作中。',
    date: '2026-04-05',
  },
  {
    kind: 'reflection',
    body: '發現自己花太多時間在工具優化上，應該把更多精力放在內容產出。工具夠用就好，內容才是核心。',
    date: '2026-04-04',
  },
];

const MOCK_INSIGHTS: InsightCheck[] = [
  {
    id: 'insight-001',
    hypothesis: 'RSS pipeline 的 error rate 會在週末飆升，因為來源網站維護',
    status: 'unverified',
    age_days: 12,
  },
  {
    id: 'insight-002',
    hypothesis: '每天早上先做 LeetCode 再寫文章，文章品質會更好',
    status: 'verified',
    age_days: 30,
  },
  {
    id: 'insight-003',
    hypothesis:
      'PrimeNG 可以完全被 CDK + Tailwind 取代，不需要第三方 UI library',
    status: 'invalidated',
    age_days: 21,
  },
];
