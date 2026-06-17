import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { LearningService } from '../../../core/services/learning.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import type {
  DashboardOverview,
  ObservationConfidence,
} from '../../../core/models/learning.model';
import {
  DashboardWidgetComponent,
  type WidgetState,
} from './dashboard-widget.component';
import { NextUpCardComponent } from './next-up-card.component';
import {
  SIGNAL_CLASS,
  STAGE_BADGE_CLASS,
  buildWeekActivity,
  computeAvgMasteryPercent,
  computeStagePills,
  deriveWeaknesses,
  sortByMastery,
} from './dashboard-view';

/**
 * Learning dashboard. Five widgets over two live reads: GET
 * /api/admin/learning/dashboard backs Mastery overview, Concepts, Recent
 * observations, and Concept weakness signals; GET /api/admin/learning/summary
 * backs Streak. Each widget renders its own loading / error / empty state,
 * so one failing read never blanks the page.
 */
@Component({
  selector: 'app-learning-dashboard-page',
  standalone: true,
  imports: [DatePipe, DashboardWidgetComponent, NextUpCardComponent],
  templateUrl: './learning-dashboard.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class LearningDashboardPageComponent {
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly confidenceFilterOptions = ['high', 'all'] as const;
  protected readonly confidenceFilter = signal<ObservationConfidence | 'all'>(
    'high',
  );

  protected readonly stageBadge = STAGE_BADGE_CLASS;
  protected readonly signalColor = SIGNAL_CLASS;

  private readonly dashboardResource = rxResource({
    params: () => this.confidenceFilter(),
    stream: ({ params }) =>
      this.learningService.dashboard({
        view: 'overview',
        confidence_filter: params,
      }),
  });

  private readonly summaryResource = rxResource({
    stream: () => this.learningService.summary(),
  });

  // resource.value() throws while a resource is in the error state, so
  // every downstream read goes through these hasValue()-guarded views.
  protected readonly overview = computed(() =>
    this.dashboardResource.hasValue()
      ? this.dashboardResource.value()
      : undefined,
  );
  protected readonly summary = computed(() =>
    this.summaryResource.hasValue() ? this.summaryResource.value() : undefined,
  );

  /** Shared by Mastery overview and Concepts — both render concept rows. */
  protected readonly conceptsState = computed(() =>
    this.dashboardWidgetState((v) => v.concepts.rows.length === 0),
  );
  protected readonly observationsState = computed(() =>
    this.dashboardWidgetState((v) => v.recent_observations.length === 0),
  );
  protected readonly weaknessState = computed(() =>
    this.dashboardWidgetState(
      (v) => !v.concepts.rows.some((r) => r.mastery_stage === 'struggling'),
    ),
  );
  protected readonly streakState = computed<WidgetState>(() => {
    if (this.summaryResource.status() === 'error') return 'error';
    return this.summary() ? 'ok' : 'loading';
  });

  protected readonly masteryMeta = computed(() => {
    const v = this.overview();
    return v ? `${v.concepts.count_total} concepts` : '';
  });
  protected readonly observationsMeta = computed(() => {
    const v = this.overview();
    return v ? `${v.recent_observations.length} recent` : '';
  });
  protected readonly weaknessMeta = computed(
    () => `${this.weaknesses().length} flagged`,
  );

  protected readonly stagePills = computed(() =>
    computeStagePills(this.overview()?.concepts.rows ?? []),
  );
  protected readonly avgMasteryPercent = computed(() =>
    computeAvgMasteryPercent(this.overview()?.concepts.rows ?? []),
  );
  protected readonly conceptRows = computed(() =>
    sortByMastery(this.overview()?.concepts.rows ?? []),
  );
  protected readonly weaknesses = computed(() =>
    deriveWeaknesses(this.overview()),
  );
  // The week heatmap rides the dashboard read (week_activity), not the
  // streak summary — empty until the dashboard resolves.
  protected readonly weekActivity = computed(() =>
    buildWeekActivity(this.overview()?.week_activity),
  );

  constructor() {
    this.topbar.set({
      title: 'Learning dashboard',
      crumbs: ['learning', 'dashboard'],
      actions: [
        {
          id: 'learning-concepts',
          label: 'Concepts',
          kind: 'secondary',
          run: () => void this.router.navigate(['/admin/learning/concepts']),
        },
      ],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setConfidenceFilter(value: ObservationConfidence | 'all'): void {
    this.confidenceFilter.set(value);
  }

  protected retryDashboard(): void {
    this.dashboardResource.reload();
  }

  protected retrySummary(): void {
    this.summaryResource.reload();
  }

  protected openConcept(slug: string, domain: string): void {
    void this.router.navigate(['/admin/learning/concepts', slug], {
      queryParams: { domain },
    });
  }

  protected percent(value: number): number {
    return Math.round(value * 100);
  }

  /** Shared state machine for the four widgets backed by the dashboard read. */
  private dashboardWidgetState(
    isEmpty: (v: DashboardOverview) => boolean,
  ): WidgetState {
    if (this.dashboardResource.status() === 'error') return 'error';
    const v = this.overview();
    if (!v) return 'loading';
    return isEmpty(v) ? 'empty' : 'ok';
  }
}
