import { Injectable, inject } from '@angular/core';
import { Observable, combineLatest, map, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ContentService } from '../../../core/services/content.service';
import { HypothesisService } from '../../../core/services/hypothesis.service';
import { TaskService } from '../../../core/services/task.service';
import { DailyPlanService } from '../../../core/services/daily-plan.service';
import { LearningService } from '../../../core/services/learning.service';
import { SystemService } from '../../../core/services/system.service';
import type { ApiContent } from '../../../core/models/api.model';
import type {
  CoordinationTask,
  DailyPlanItem,
  DailyPlanResponse,
  Hypothesis,
  LearningSummary,
} from '../../../core/models/workbench.model';
import type { SystemHealth } from '../../../core/models/admin.model';

/** Row surfaced in the HERO "Awaiting your judgment" section. */
export interface JudgmentRow {
  kind: 'content' | 'hypothesis' | 'task';
  id: string;
  title: string;
  subtitle: string;
  submittedAt: string;
  ageDays: number;
  /** Three-letter visual badge (ART/ESS/BLG/TIL/DGT/HYP/TSK). */
  badge: string;
  /** Route to open when the row is activated. */
  route: string | null;
}

const CONTENT_TYPE_BADGE: Record<ApiContent['type'], string> = {
  article: 'ART',
  essay: 'ESS',
  'build-log': 'BLG',
  til: 'TIL',
  digest: 'DGT',
};

export interface PlanSummary {
  date: string;
  items: DailyPlanItem[];
  total: number;
  done: number;
  overdue: number;
}

export type WarningSeverity = 'warn' | 'error';

export interface TodayWarning {
  severity: WarningSeverity;
  source: 'feed' | 'pipeline' | 'goal';
  message: string;
}

export interface TodayVm {
  date: string;
  awaitingJudgment: JudgmentRow[];
  plan: PlanSummary | null;
  dueReviewsCount: number;
  warnings: TodayWarning[];
}

/**
 * Today page composer. Until `GET /api/admin/commitment/today` ships per
 *, this service fans out to the existing per-entity
 * endpoints and assembles the Today envelope. Each source degrades
 * independently — one failing dependency does not blank the whole view.
 *
 * Swap this to a single-endpoint call (`CommitmentService.today()`) once
 * the backend lands `/commitment/today`; the `TodayVm` shape stays the
 * same.
 */
@Injectable({ providedIn: 'root' })
export class TodayService {
  private readonly contentService = inject(ContentService);
  private readonly hypothesisService = inject(HypothesisService);
  private readonly taskService = inject(TaskService);
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly learningService = inject(LearningService);
  private readonly systemService = inject(SystemService);

  today(): Observable<TodayVm> {
    return combineLatest([
      this.reviewContents(),
      this.unverifiedHypotheses(),
      this.completedTasks(),
      this.plan(),
      this.learningSummary(),
      this.systemHealth(),
    ]).pipe(
      map(
        ([contents, hypotheses, tasks, plan, learning, health]): TodayVm => ({
          date: todayIso(),
          awaitingJudgment: [
            ...contents.map(contentRow),
            ...hypotheses.map(hypothesisRow),
            ...tasks.map(taskRow),
          ].sort(
            (a, b) =>
              new Date(a.submittedAt).getTime() -
              new Date(b.submittedAt).getTime(),
          ),
          plan,
          dueReviewsCount: learning?.due_reviews ?? 0,
          warnings: buildWarnings(health),
        }),
      ),
    );
  }

  private reviewContents(): Observable<ApiContent[]> {
    return this.contentService
      .adminList({ status: 'review', perPage: 50 })
      .pipe(
        map((r) => r.data),
        catchError(() => of<ApiContent[]>([])),
      );
  }

  private unverifiedHypotheses(): Observable<Hypothesis[]> {
    return this.hypothesisService
      .list('unverified')
      .pipe(catchError(() => of<Hypothesis[]>([])));
  }

  private completedTasks(): Observable<CoordinationTask[]> {
    return this.taskService
      .completed()
      .pipe(catchError(() => of<CoordinationTask[]>([])));
  }

  private plan(): Observable<PlanSummary | null> {
    return this.dailyPlanService.today().pipe(
      map((r: DailyPlanResponse) => ({
        date: r.date,
        items: r.items,
        total: r.total,
        done: r.done,
        overdue: r.overdue_count,
      })),
      catchError(() => of<PlanSummary | null>(null)),
    );
  }

  private learningSummary(): Observable<LearningSummary | null> {
    return this.learningService
      .summary()
      .pipe(catchError(() => of<LearningSummary | null>(null)));
  }

  private systemHealth(): Observable<SystemHealth | null> {
    return this.systemService
      .getHealth()
      .pipe(catchError(() => of<SystemHealth | null>(null)));
  }
}

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function daysSince(dateStr: string): number {
  const diff = Date.now() - new Date(dateStr).getTime();
  return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
}

function contentRow(c: ApiContent): JudgmentRow {
  const readingTime = c.reading_time_min ?? 0;
  const subtitle =
    readingTime > 0 ? `${c.type} · ${readingTime} min read` : c.type;
  return {
    kind: 'content',
    id: c.id,
    title: c.title,
    subtitle,
    submittedAt: c.updated_at,
    ageDays: daysSince(c.updated_at),
    badge: CONTENT_TYPE_BADGE[c.type] ?? 'CNT',
    route: `/admin/knowledge/content/${c.id}/edit`,
  };
}

function hypothesisRow(h: Hypothesis): JudgmentRow {
  return {
    kind: 'hypothesis',
    id: h.id,
    title: h.claim,
    subtitle: `unverified · ${h.created_by}`,
    submittedAt: h.created_at,
    ageDays: daysSince(h.created_at),
    badge: 'HYP',
    route: null,
  };
}

function taskRow(t: CoordinationTask): JudgmentRow {
  const when = t.completed_at ?? t.submitted_at;
  return {
    kind: 'task',
    id: t.id,
    title: t.title,
    subtitle: `${t.source} → ${t.target} · completed`,
    submittedAt: when,
    ageDays: daysSince(when),
    badge: 'TSK',
    route: null,
  };
}

function buildWarnings(health: SystemHealth | null): TodayWarning[] {
  if (!health) return [];

  const warnings: TodayWarning[] = [];

  for (const feed of health.feeds.failing_feeds) {
    warnings.push({
      severity: 'warn',
      source: 'feed',
      message: `${feed.name} failing — ${feed.error}`,
    });
  }

  if (health.pipelines.failed > 0) {
    warnings.push({
      severity: 'error',
      source: 'pipeline',
      message: `${health.pipelines.failed} pipeline runs failed in the last 24h`,
    });
  }

  return warnings;
}
