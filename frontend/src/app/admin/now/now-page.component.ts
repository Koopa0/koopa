import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';
import { ContentService } from '../../core/services/content.service';
import { HypothesisService } from '../../core/services/hypothesis.service';
import { TaskService } from '../../core/services/task.service';
import { PlanService } from '../../core/services/plan.service';
import { SystemService } from '../../core/services/system.service';
import { DailyPlanService } from '../../core/services/daily-plan.service';
import { LearningService } from '../../core/services/learning.service';
import { AgentService } from '../../core/services/agent.service';
import { InspectorService } from '../inspector/inspector.service';
import {
  ENTITY_TYPE_META,
  type EntityTypeMeta,
  type InspectorTargetType,
  type JudgmentQueueItem,
  type GoalSummary,
  type Hypothesis,
  type CoordinationTask,
  type DailyPlanResponse,
  type LearningSummary,
  type AgentsResponse,
  type CellState,
} from '../../core/models/workbench.model';
import type { ApiContent } from '../../core/models/api.model';
import type { SystemHealth } from '../../core/models/admin.model';

type TimeMode = 'now' | 'week';

/**
 * Home page — adaptive layout workbench.
 *
 * When judgment queue has items → queue is hero, overview grid below.
 * When queue is empty → overview grid promotes to hero.
 *
 * Judgment queue aggregates: content in review + completed tasks + unverified hypotheses.
 * Currently only content API exists; hypothesis and task show as empty until APIs are built.
 */
@Component({
  selector: 'app-now-page',
  standalone: true,
  imports: [],
  templateUrl: './now-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NowPageComponent {
  private readonly contentService = inject(ContentService);
  private readonly hypothesisService = inject(HypothesisService);
  private readonly taskService = inject(TaskService);
  private readonly planService = inject(PlanService);
  private readonly systemService = inject(SystemService);
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly learningService = inject(LearningService);
  private readonly agentService = inject(AgentService);
  protected readonly inspector = inject(InspectorService);

  protected readonly timeMode = signal<TimeMode>('now');

  /** Entity metadata lookup. See inspector-panel for why this is a method. */
  protected meta(type: InspectorTargetType): EntityTypeMeta {
    return ENTITY_TYPE_META[type];
  }

  // === Judgment Queue (3 sources) ===

  private readonly contentInReview = rxResource<ApiContent[], void>({
    stream: () =>
      this.contentService
        .adminList({ type: undefined, is_public: undefined })
        .pipe(map((r) => r.data.filter((c) => c.status === 'review'))),
  });

  private readonly unverifiedHypotheses = rxResource<Hypothesis[], void>({
    stream: () => this.hypothesisService.list('unverified'),
  });

  private readonly completedTasks = rxResource<CoordinationTask[], void>({
    stream: () => this.taskService.completed(),
  });

  /** Merged judgment queue — content + hypothesis + task, sorted by age. */
  protected readonly queueItems = computed<JudgmentQueueItem[]>(() => {
    const content = this.contentInReview.value() ?? [];
    const hypotheses = this.unverifiedHypotheses.value() ?? [];
    const tasks = this.completedTasks.value() ?? [];

    const items: JudgmentQueueItem[] = [
      ...content.map(
        (c): JudgmentQueueItem => ({
          type: 'content',
          id: c.id,
          title: c.title,
          subtitle: `${c.type} · ${c.reading_time_min} min`,
          submitted_at: c.updated_at,
          age_days: this.daysSince(c.updated_at),
        }),
      ),
      ...hypotheses.map(
        (h): JudgmentQueueItem => ({
          type: 'hypothesis',
          id: h.id,
          title: h.claim,
          subtitle: `unverified · ${h.created_by}`,
          submitted_at: h.created_at,
          age_days: this.daysSince(h.created_at),
        }),
      ),
      ...tasks.map(
        (t): JudgmentQueueItem => ({
          type: 'task',
          id: t.id,
          title: t.title,
          subtitle: `${t.source} → ${t.target} · completed`,
          submitted_at: t.completed_at ?? t.submitted_at,
          age_days: this.daysSince(t.completed_at ?? t.submitted_at),
        }),
      ),
    ];

    return items.sort(
      (a, b) =>
        new Date(a.submitted_at).getTime() - new Date(b.submitted_at).getTime(),
    );
  });

  protected readonly hasQueue = computed(() => this.queueItems().length > 0);
  protected readonly isQueueLoading = computed(
    () =>
      this.contentInReview.status() === 'loading' &&
      this.unverifiedHypotheses.status() === 'loading' &&
      this.completedTasks.status() === 'loading',
  );

  // === Overview: Goals ===

  protected readonly goalsResource = rxResource<GoalSummary[], void>({
    stream: () =>
      this.planService.getGoalsOverview().pipe(
        map((r) =>
          r.goals
            .filter(
              (g) => g.status === 'in_progress' || g.status === 'not_started',
            )
            .map((g) => ({
              id: g.id,
              title: g.title,
              status: g.status,
              deadline: g.deadline ?? undefined,
              milestones_total: g.milestones_total,
              milestones_done: g.milestones_done,
              area_name: g.area_name,
            })),
        ),
      ),
  });

  protected readonly activeGoals = computed(
    () => this.goalsResource.value() ?? [],
  );

  // === Overview: System ===

  protected readonly systemResource = rxResource<SystemHealth, void>({
    stream: () => this.systemService.getHealth(),
  });

  protected readonly system = computed(
    () => this.systemResource.value() ?? null,
  );

  // === Overview: Content counts ===

  protected readonly contentCountsResource = rxResource<
    { drafts: number; inReview: number },
    void
  >({
    stream: () =>
      this.contentService.adminList().pipe(
        map((r) => ({
          drafts: r.data.filter((c) => c.status === 'draft').length,
          inReview: r.data.filter((c) => c.status === 'review').length,
        })),
      ),
  });

  protected readonly contentCounts = computed(
    () => this.contentCountsResource.value() ?? { drafts: 0, inReview: 0 },
  );

  /** CONTENT cell state — warn when >= 5 items in review (governance backlog signal). */
  protected readonly contentCellState = computed<CellState>(() => {
    const review = this.contentCounts().inReview;
    if (review >= 5) {
      return { state: 'warn', reason: `${review} awaiting review` };
    }
    return { state: 'ok' };
  });

  // === Overview: Today Plan ===

  protected readonly dailyPlanResource = rxResource<DailyPlanResponse, void>({
    stream: () => this.dailyPlanService.today(),
  });

  protected readonly dailyPlan = computed(
    () => this.dailyPlanResource.value() ?? null,
  );

  /**
   * Status glyph stream for compact progress display: ✓ done, ● in progress
   * (planned + todo_state in_progress), · planned. Capped at 8 glyphs.
   */
  protected readonly dailyPlanGlyphs = computed<string[]>(() => {
    const plan = this.dailyPlan();
    if (!plan) return [];
    return plan.items.slice(0, 8).map((item) => {
      if (item.status === 'done') return '✓';
      if (item.status === 'planned' && item.todo_state === 'in_progress')
        return '●';
      if (item.status === 'deferred' || item.status === 'dropped') return '·';
      return '·';
    });
  });

  /**
   * Top 1-2 active items shown by title for context. Excludes done/deferred/dropped.
   * Includes both planned items and items currently in_progress (todo lifecycle)
   * — both are "active" from the workbench owner's POV.
   */
  protected readonly dailyPlanTopActive = computed(() => {
    const plan = this.dailyPlan();
    if (!plan) return [];
    return plan.items
      .filter(
        (it) =>
          it.status === 'planned' &&
          (it.todo_state === 'todo' || it.todo_state === 'in_progress'),
      )
      .slice(0, 2)
      .map((it) => ({ id: it.todo_id, title: it.todo_title }));
  });

  protected readonly dailyPlanCellState = computed<CellState>(() => {
    const plan = this.dailyPlan();
    if (!plan) return { state: 'ok' };
    return { state: plan.state, reason: plan.reason };
  });

  // === Overview: Learning ===

  protected readonly learningResource = rxResource<LearningSummary, void>({
    stream: () => this.learningService.summary(),
  });

  protected readonly learning = computed(
    () => this.learningResource.value() ?? null,
  );

  protected readonly learningCellState = computed<CellState>(() => {
    const summary = this.learning();
    if (!summary) return { state: 'ok' };
    return { state: summary.state, reason: summary.reason };
  });

  /** Total weak count across domains — for compact display ("N weak"). */
  protected readonly learningWeakTotal = computed(() => {
    const summary = this.learning();
    if (!summary) return 0;
    return summary.domains.reduce((sum, d) => sum + d.concepts_weak, 0);
  });

  // === Overview: Agents ===

  protected readonly agentsResource = rxResource<AgentsResponse, void>({
    stream: () => this.agentService.list(),
  });

  protected readonly agents = computed(
    () => this.agentsResource.value() ?? null,
  );

  /**
   * Filter to agents the workbench cares about — those that submit OR receive
   * tasks. Excludes "human" and the dev-tooling agents (claude, koopa0-dev,
   * go-spec) which clutter the cell with non-actionable rows.
   */
  protected readonly visibleAgents = computed(() => {
    const resp = this.agents();
    if (!resp) return [];
    return resp.agents.filter(
      (a) =>
        a.platform === 'claude-cowork' &&
        (a.capability.submit_tasks || a.capability.receive_tasks),
    );
  });

  protected readonly agentsCellState = computed<CellState>(() => {
    const resp = this.agents();
    if (!resp) return { state: 'ok' };
    return { state: resp.state, reason: resp.reason };
  });

  // === Auto-advance ===

  /** Track which queue item is currently active in the inspector. */
  private readonly activeQueueIndex = computed(() => {
    const target = this.inspector.target();
    if (!target) return -1;
    return this.queueItems().findIndex(
      (item) => item.type === target.type && item.id === target.id,
    );
  });

  constructor() {
    // Watch lastAction and auto-advance to next queue item.
    effect(() => {
      const action = this.inspector.lastAction();
      if (!action) return;

      const items = this.queueItems();
      const currentIdx = items.findIndex(
        (item) => item.type === action.type && item.id === action.id,
      );

      // Reload all queue sources after action
      this.contentInReview.reload();
      this.unverifiedHypotheses.reload();
      this.completedTasks.reload();

      // Advance to next item, or close if queue is empty
      const nextIdx = currentIdx + 1;
      if (nextIdx < items.length) {
        const next = items[nextIdx];
        this.inspector.open({ type: next.type, id: next.id });
      } else if (currentIdx > 0) {
        // Wrapped past end — go to first remaining
        const first = items[0];
        if (first.id !== action.id) {
          this.inspector.open({ type: first.type, id: first.id });
        } else {
          this.inspector.close();
        }
      } else {
        this.inspector.close();
      }
    });
  }

  // === Actions ===

  protected openInspector(item: JudgmentQueueItem): void {
    this.inspector.open({ type: item.type, id: item.id });
  }

  protected setTimeMode(mode: TimeMode): void {
    this.timeMode.set(mode);
  }

  protected milestonePercent(done: number, total: number): number {
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
  }

  private daysSince(dateStr: string): number {
    const diff = Date.now() - new Date(dateStr).getTime();
    return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
  }
}
