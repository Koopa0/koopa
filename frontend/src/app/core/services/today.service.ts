import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
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
    return this.api.getData<MyDayContext>('/api/admin/today');
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
