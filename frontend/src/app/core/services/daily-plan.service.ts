import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { DailyPlanResponse } from '../models/workbench.model';

/**
 * Daily Plan service — today's planned todos for the TODAY PLAN cell.
 * The response carries `state` + `reason`; the frontend only renders
 * them, it never derives the state itself.
 */
@Injectable({ providedIn: 'root' })
export class DailyPlanService {
  private readonly api = inject(ApiService);

  /** Today's plan. Optional `date` (YYYY-MM-DD) overrides server today. */
  today(date?: string): Observable<DailyPlanResponse> {
    const params = date ? { date } : undefined;
    return this.api.getData<DailyPlanResponse>(
      '/api/admin/commitment/daily-plan',
      params,
    );
  }
}
