import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { ApiService } from './api.service';
import type {
  MyDayContext,
  DailyItemAction,
  DailyPlanItem,
} from '../models/admin.model';

/** 今日計畫服務 — My Day 語意 API */
@Injectable({ providedIn: 'root' })
export class TodayService {
  private readonly api = inject(ApiService);

  /** 取得今日全部脈絡：計畫項目、未完成、逾期、目標脈搏 */
  getMyDayContext(): Observable<MyDayContext> {
    // TODO: replace with real API when backend implements
    // return this.api.getData<MyDayContext>('/api/admin/today');
    return of(MOCK_TODAY);
  }

  /** 批次規劃今日項目 */
  planToday(
    items: {
      task_id: string;
      position: number;
      estimated_minutes?: number;
    }[],
  ): Observable<DailyPlanItem[]> {
    return this.api.postData<DailyPlanItem[]>('/api/admin/today/plan', {
      items,
    });
  }

  /** 解決單一每日項目（完成、推遲、放棄） */
  resolveDailyItem(itemId: string, action: DailyItemAction): Observable<void> {
    return this.api.postVoid(`/api/admin/today/items/${itemId}/resolve`, {
      action,
    });
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位須嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_TODAY: MyDayContext = {
  date: '2026-04-08',
  context_line: '距離 GDE 申請還有 47 天。本週 focus: Admin redesign。',
  yesterday_unfinished: [
    {
      id: 'dpi-y01',
      task_id: 'task-098',
      title: 'Add dark mode toggle to settings page',
      area: 'frontend',
      energy: 'medium',
      estimated_minutes: 45,
      position: 2,
      status: 'planned',
      planned_date: '2026-04-07',
    },
  ],
  today_plan: [
    {
      id: 'dpi-001',
      task_id: 'task-101',
      title: 'Implement admin sidebar navigation',
      area: 'frontend',
      energy: 'high',
      estimated_minutes: 90,
      position: 1,
      status: 'planned',
      planned_date: '2026-04-08',
    },
    {
      id: 'dpi-002',
      task_id: 'task-102',
      title: 'Write pgx integration tests for content store',
      area: 'backend',
      energy: 'high',
      estimated_minutes: 60,
      position: 2,
      status: 'planned',
      planned_date: '2026-04-08',
    },
    {
      id: 'dpi-003',
      task_id: 'task-103',
      title: 'Review RSS pipeline error handling',
      area: 'backend',
      energy: 'medium',
      estimated_minutes: 30,
      position: 3,
      status: 'done',
      planned_date: '2026-04-08',
    },
  ],
  overdue_tasks: [
    {
      id: 'task-090',
      title: 'Migrate Obsidian sync to NATS JetStream',
      due: '2026-04-05',
      area: 'backend',
      priority: 'high',
    },
  ],
  needs_attention: {
    inbox_count: 4,
    pending_directives: 1,
    unread_reports: 0,
    due_reviews: 3,
    overdue_tasks: 1,
  },
  goal_pulse: [
    {
      id: 'goal-001',
      title: 'Ship koopa0.dev v1 public launch',
      area: 'backend',
      deadline: '2026-06-30',
      days_remaining: 83,
      milestones_total: 5,
      milestones_done: 3,
      next_milestone: 'Admin UI redesign complete',
      status: 'in-progress',
    },
    {
      id: 'goal-002',
      title: 'Publish 12 technical articles by Q2',
      area: 'learning',
      deadline: '2026-06-30',
      days_remaining: 83,
      milestones_total: 12,
      milestones_done: 4,
      next_milestone: '5th article published',
      status: 'in-progress',
    },
    {
      id: 'goal-003',
      title: 'Apply for Google Developer Expert',
      area: 'career',
      deadline: '2026-05-25',
      days_remaining: 47,
      milestones_total: 4,
      milestones_done: 2,
      next_milestone: 'Community contribution portfolio ready',
      status: 'in-progress',
    },
  ],
};
