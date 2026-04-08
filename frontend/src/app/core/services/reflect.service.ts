import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
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
  getDailyContext(date?: string): Observable<DailyReflectionContext> {
    const params: Record<string, string> = {};
    if (date) {
      params['date'] = date;
    }
    return this.api.getData<DailyReflectionContext>(
      '/api/admin/reflect/daily',
      params,
    );
  }

  /** 取得週報 context */
  getWeeklyContext(weekStart?: string): Observable<WeeklyReviewContext> {
    const params: Record<string, string> = {};
    if (weekStart) {
      params['week_start'] = weekStart;
    }
    return this.api.getData<WeeklyReviewContext>(
      '/api/admin/reflect/weekly',
      params,
    );
  }

  /** 寫入日誌條目 */
  writeJournal(entry: JournalEntry): Observable<void> {
    return this.api.postVoid('/api/admin/reflect/journal', entry);
  }

  /** 取得日誌條目列表 */
  getJournalEntries(limit?: number): Observable<JournalEntry[]> {
    const params: Record<string, string | number> = {};
    if (limit !== undefined) {
      params['limit'] = limit;
    }
    return this.api.getData<JournalEntry[]>(
      '/api/admin/reflect/journal',
      params,
    );
  }

  /** 取得洞察列表 */
  getInsights(): Observable<InsightCheck[]> {
    return this.api.getData<InsightCheck[]>('/api/admin/reflect/insights');
  }
}
