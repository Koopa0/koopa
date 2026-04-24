import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  LearningService,
  type ReviewRating,
} from '../../../core/services/learning.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import type {
  DashboardOverview,
  ObservationConfidence,
} from '../../../core/models/learning.model';

const RATINGS: readonly ReviewRating[] = ['again', 'hard', 'good', 'easy'];
const RATING_CLASS: Record<ReviewRating, string> = {
  again: 'text-red-300 hover:bg-red-950/40',
  hard: 'text-amber-300 hover:bg-amber-950/40',
  good: 'text-sky-300 hover:bg-sky-950/40',
  easy: 'text-emerald-300 hover:bg-emerald-950/40',
};

/**
 * Learning Dashboard / Three cards from
 * the overview view: Concepts, Due today (FSRS), Recent observations.
 * All backing endpoints are ; the page degrades gracefully when
 * the backend 404/405/501s.
 */
@Component({
  selector: 'app-learning-dashboard-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
  templateUrl: './learning-dashboard.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class LearningDashboardPageComponent {
  private readonly learningService = inject(LearningService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly ratings = RATINGS;

  protected readonly confidenceFilterOptions: readonly (
    | ObservationConfidence
    | 'all'
  )[] = ['high', 'all'];

  protected readonly confidenceFilter = signal<ObservationConfidence | 'all'>(
    'high',
  );

  protected readonly resource = rxResource<
    DashboardOverview,
    ObservationConfidence | 'all'
  >({
    params: () => this.confidenceFilter(),
    stream: ({ params }) =>
      this.learningService.dashboard({
        view: 'overview',
        confidence_filter: params,
      }),
  });

  protected readonly vm = computed(() => this.resource.value());
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.vm(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly endpointsUnavailable = computed(() => {
    if (this.resource.status() !== 'error') return false;
    const err = this.resource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  private readonly _ratingInFlight = signal<string | null>(null);
  protected readonly ratingInFlight = this._ratingInFlight.asReadonly();

  protected readonly masteryCounts = computed(() => {
    const vm = this.vm();
    if (!vm) return { struggling: 0, developing: 0, solid: 0 };
    const rows = vm.concepts.rows;
    return {
      struggling: rows.filter((r) => r.mastery_stage === 'struggling').length,
      developing: rows.filter((r) => r.mastery_stage === 'developing').length,
      solid: rows.filter((r) => r.mastery_stage === 'solid').length,
    };
  });

  constructor() {
    this.topbar.set({
      title: 'Learning dashboard',
      crumbs: ['Learning'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setConfidenceFilter(value: ObservationConfidence | 'all'): void {
    this.confidenceFilter.set(value);
  }

  protected ratingClass(r: ReviewRating): string {
    return RATING_CLASS[r];
  }

  protected openConcept(slug: string): void {
    this.router.navigate(['/admin/learning/concepts', slug]);
  }

  protected recordReview(cardId: string, rating: ReviewRating): void {
    if (this._ratingInFlight()) return;
    this._ratingInFlight.set(cardId);
    this.learningService.recordReview(cardId, rating).subscribe({
      next: () => {
        this._ratingInFlight.set(null);
        this.notifications.success(`Recorded ${rating}.`);
        this.resource.reload();
      },
      error: (err: unknown) => {
        this._ratingInFlight.set(null);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        if (status === 404 || status === 405 || status === 501) {
          this.notifications.info(
            'Endpoint not yet available in backend (review).',
          );
        } else {
          this.notifications.error('Failed to record review.');
        }
      },
    });
  }

  protected masteryStagePercent(value: number): number {
    return Math.round(value * 100);
  }

  protected masteryStageColor(stage: string): string {
    switch (stage) {
      case 'solid':
        return 'bg-emerald-500';
      case 'developing':
        return 'bg-sky-400';
      case 'struggling':
        return 'bg-red-400';
      default:
        return 'bg-zinc-500';
    }
  }
}
