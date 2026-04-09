import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  MyDayContext,
  DailyItemAction,
  DailyPlanItem,
} from '../models/admin.model';

/** Today planning service — My Day semantic API */
@Injectable({ providedIn: 'root' })
export class TodayService {
  private readonly api = inject(ApiService);

  /** Get today's full context: plan items, unfinished, overdue, goal pulse */
  getMyDayContext(): Observable<MyDayContext> {
    return this.api.getData<MyDayContext>('/api/admin/today');
  }

  /** Batch plan today's items */
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

  /** Resolve a single daily item (complete, defer, drop) */
  resolveDailyItem(itemId: string, action: DailyItemAction): Observable<void> {
    return this.api.postVoid(`/api/admin/today/items/${itemId}/resolve`, {
      action,
    });
  }
}
