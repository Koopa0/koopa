import { Injectable, inject } from '@angular/core';
import { forkJoin, of, type Observable } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import {
  DailyPlanService,
  type DailyPlan,
} from '../../../core/services/daily-plan.service';
import {
  NoteService,
  type NoteDetail,
} from '../../../core/services/note.service';
import {
  DAY_CLOSE_LOOKBACK_DAYS,
  buildUnclosedDays,
  lookbackDates,
  type UnclosedDay,
} from './day-close-view';

/**
 * Day-close orchestration — confronts every unclosed day in the lookback
 * window. Frontend-only over existing endpoints: it probes
 * GET /commitment/daily-plan per past date (no "unclosed days" endpoint
 * exists), keeps the days that still carry unresolved planned items, and
 * delegates the resolution actions (re-plan / drop) to the existing
 * daily-plan and todo services from the page. The one-line reflection is
 * a draft musing note via the notes endpoint.
 *
 * The per-date reads are independent and the surface is single-user
 * admin, so they run in parallel; a single failed probe degrades to "no
 * plan that day" rather than failing the whole confrontation.
 */
@Injectable({ providedIn: 'root' })
export class DayCloseService {
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly noteService = inject(NoteService);

  /**
   * Probe the last {@link DAY_CLOSE_LOOKBACK_DAYS} days (excluding today)
   * and return only those with unresolved planned items, newest first.
   * `today` is injectable for deterministic tests; it defaults to now.
   */
  unclosedDays(today: Date = new Date()): Observable<UnclosedDay[]> {
    const dates = lookbackDates(today, DAY_CLOSE_LOOKBACK_DAYS);
    const probes = dates.map((date) =>
      this.dailyPlanService.today(date).pipe(
        // A failed probe (or a date with no plan) contributes an empty
        // plan rather than collapsing the whole forkJoin.
        catchError(() => of(emptyPlan(date))),
      ),
    );
    return forkJoin(probes).pipe(map((plans) => buildUnclosedDays(plans)));
  }

  /** Read today's plan — needed to build the re-plan append body. */
  today(): Observable<DailyPlan> {
    return this.dailyPlanService.today();
  }

  /** Save the optional one-line close reflection as a draft musing note. */
  saveReflection(title: string, body: string): Observable<NoteDetail> {
    return this.noteService.create({ title, body, kind: 'musing' });
  }
}

/** An empty plan stand-in for a date with no committed rows / a failed probe. */
function emptyPlan(date: string): DailyPlan {
  return { date, items: [], total: 0, done: 0, overdue_count: 0 };
}
