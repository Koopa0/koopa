import { Injectable, Signal, computed, inject } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { combineLatest, map, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { BookmarkService } from '../../core/services/bookmark.service';
import { ContentService } from '../../core/services/content.service';
import { HypothesisService } from '../../core/services/hypothesis.service';
import { PlanService } from '../../core/services/plan.service';
import { SystemService } from '../../core/services/system.service';
import { TaskService } from '../../core/services/task.service';

/**
 * Keys map one-to-one to the `system/health` envelope fields. Any nav
 * item without a key renders without a count.
 */
export type NavCountKey =
  | 'todos_open'
  | 'goals_active'
  | 'contents_total'
  | 'review_queue'
  | 'bookmarks_total'
  | 'feeds_active'
  | 'hypotheses_unverified'
  | 'tasks_awaiting_human';

export type NavCountEnvelope = Record<NavCountKey, number | null>;

const EMPTY_ENVELOPE: NavCountEnvelope = {
  todos_open: null,
  goals_active: null,
  contents_total: null,
  review_queue: null,
  bookmarks_total: null,
  feeds_active: null,
  hypotheses_unverified: null,
  tasks_awaiting_human: null,
};

/**
 * Fans out to per-entity endpoints and assembles the nav-count envelope
 * the admin shell renders. Each source is wrapped in
 * `catchError` → `null` so one failing dependency doesn't blank the
 * whole envelope; the nav simply hides that count.
 *
 * Backed by {@link rxResource} so the shell can call {@link reload}
 * after mutations (publish, request-revision, …) to refresh the
 * `review_queue` and `tasks_awaiting_human` counts without a full
 * page reload.
 */
@Injectable({ providedIn: 'root' })
export class AdminNavCountsService {
  private readonly contentService = inject(ContentService);
  private readonly hypothesisService = inject(HypothesisService);
  private readonly taskService = inject(TaskService);
  private readonly planService = inject(PlanService);
  private readonly bookmarkService = inject(BookmarkService);
  private readonly systemService = inject(SystemService);

  private readonly resource = rxResource<NavCountEnvelope, void>({
    stream: () =>
      combineLatest({
        contents_total: this.contentService.adminList({ perPage: 1 }).pipe(
          map((r) => r.meta.total ?? r.data.length),
          catchError(() => of<number | null>(null)),
        ),
        review_queue: this.contentService
          .adminList({ status: 'review', perPage: 1 })
          .pipe(
            map((r) => r.meta.total ?? r.data.length),
            catchError(() => of<number | null>(null)),
          ),
        goals_active: this.planService.getGoalsOverview().pipe(
          map(
            (o) =>
              o.goals.filter(
                (g) => g.status === 'in_progress' || g.status === 'not_started',
              ).length,
          ),
          catchError(() => of<number | null>(null)),
        ),
        hypotheses_unverified: this.hypothesisService.list('unverified').pipe(
          map((list) => list.length),
          catchError(() => of<number | null>(null)),
        ),
        tasks_awaiting_human: this.taskService.open().pipe(
          map(
            (list) =>
              list.filter(
                (t) =>
                  t.state === 'revision_requested' || t.state === 'submitted',
              ).length,
          ),
          catchError(() => of<number | null>(null)),
        ),
        bookmarks_total: this.bookmarkService.list({ perPage: 1 }).pipe(
          map((r) => r.meta.total ?? r.data.length),
          catchError(() => of<number | null>(null)),
        ),
        feeds_active: this.systemService.getHealth().pipe(
          map((h) => h.feeds.healthy),
          catchError(() => of<number | null>(null)),
        ),
      }).pipe(
        map((partial): NavCountEnvelope => ({ ...EMPTY_ENVELOPE, ...partial })),
        catchError(() => of(EMPTY_ENVELOPE)),
      ),
  });

  /** Signal-tracked read; lookups by key are O(1). */
  readonly counts: Signal<NavCountEnvelope> = computed(
    () => this.resource.value() ?? EMPTY_ENVELOPE,
  );

  /**
   * Re-fetch every source. Call after an admin mutation (publish,
   * revert-to-draft, request-revision, etc.) so the nav reflects the
   * new state immediately. The shell additionally reloads on
   * `NavigationEnd` — see {@link AdminLayoutComponent}.
   */
  reload(): void {
    this.resource.reload();
  }
}
