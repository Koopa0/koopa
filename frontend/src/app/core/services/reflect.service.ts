import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  DailyReflectionContext,
  WeeklyReviewContext,
  JournalEntry,
  InsightCheck,
} from '../models/admin.model';

/** Reflection service — daily review, weekly review, journal, insights */
@Injectable({ providedIn: 'root' })
export class ReflectService {
  private readonly api = inject(ApiService);

  /** Get daily reflection context */
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

  /** Get weekly review context */
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

  /** Write a journal entry */
  writeJournal(entry: JournalEntry): Observable<void> {
    return this.api.postVoid('/api/admin/reflect/journal', entry);
  }

  /** Get journal entries list */
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

  /** Get insights list */
  getInsights(): Observable<InsightCheck[]> {
    return this.api.getData<InsightCheck[]>('/api/admin/reflect/insights');
  }
}
