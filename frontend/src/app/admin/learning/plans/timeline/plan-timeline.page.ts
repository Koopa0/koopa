import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  PlanDetail,
  PlanEntryStatus,
  PlanStatus,
} from '../../../../core/models/learning.model';

const ENTRY_DOT: Record<PlanEntryStatus, string> = {
  pending: 'bg-zinc-500',
  completed: 'bg-emerald-500',
  skipped: 'bg-zinc-600',
  substituted: 'bg-amber-400',
};

const ENTRY_TEXT: Record<PlanEntryStatus, string> = {
  pending: 'text-zinc-300',
  completed: 'text-emerald-300',
  skipped: 'text-zinc-500',
  substituted: 'text-amber-300',
};

const PLAN_STATUS_TEXT: Record<PlanStatus, string> = {
  draft: 'text-zinc-400',
  active: 'text-sky-300',
  paused: 'text-amber-300',
  completed: 'text-emerald-300',
  abandoned: 'text-zinc-500',
};

/**
 * Plan Timeline Entries render in
 * position order with status dots + policy-mandatory completion
 * audit (completed_by_attempt_id + reason). .
 */
@Component({
  selector: 'app-plan-timeline-page',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './plan-timeline.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class PlanTimelinePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<PlanDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.learningService.plan(params),
  });

  protected readonly plan = computed(() => this.resource.value());
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.plan(),
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

  protected readonly progressPercent = computed(() => {
    const p = this.plan();
    if (!p || p.summary.total === 0) return 0;
    return Math.round((p.summary.completed / p.summary.total) * 100);
  });

  constructor() {
    this.topbar.set({
      title: 'Learning plan',
      crumbs: ['Learning', 'Plans'],
    });

    effect(() => {
      const p = this.plan();
      if (!p) return;
      this.topbar.set({
        title: `Plan · ${p.title}`,
        crumbs: ['Learning', 'Plans', p.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected back(): void {
    this.router.navigate(['/admin/learning']);
  }

  protected entryDot(s: PlanEntryStatus): string {
    return ENTRY_DOT[s];
  }

  protected entryText(s: PlanEntryStatus): string {
    return ENTRY_TEXT[s];
  }

  protected planStatusText(s: PlanStatus): string {
    return PLAN_STATUS_TEXT[s];
  }
}
