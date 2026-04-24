import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { TodayService, type TodayVm, type JudgmentRow } from './today.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

/**
 * Today — the Commitment landing page. Four stacked regions:
 *
 *   HERO     — content in review + unverified hypotheses + completed
 *              tasks awaiting human approval. Hidden when empty; PLAN
 *              promotes to the top.
 *   PLAN     — today's daily_plan_items with status glyphs and the
 *              top two active items for quick context.
 *   REVIEWS  — count of FSRS cards due within 24h plus a CTA to the
 *              review session.
 *   WARNINGS — cell-state envelope (failing feeds, pipeline failures).
 *              Only warn / error rows render; clean state is silent.
 *
 * Each region degrades independently: a 500 from one upstream endpoint
 * does not blank the others (see {@link TodayService}).
 */
@Component({
  selector: 'app-today-page',
  standalone: true,
  imports: [RouterLink, DatePipe],
  templateUrl: './today-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class TodayPageComponent {
  private readonly todayService = inject(TodayService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<TodayVm, void>({
    stream: () => this.todayService.today(),
  });

  protected readonly vm = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.vm(),
  );

  protected readonly hasJudgment = computed(
    () => (this.vm()?.awaitingJudgment ?? []).length > 0,
  );
  protected readonly hasPlan = computed(
    () => (this.vm()?.plan?.items ?? []).length > 0,
  );
  protected readonly hasReviews = computed(
    () => (this.vm()?.dueReviewsCount ?? 0) > 0,
  );
  protected readonly hasWarnings = computed(
    () => (this.vm()?.warnings ?? []).length > 0,
  );

  protected readonly planGlyphs = computed(() => {
    const items = this.vm()?.plan?.items ?? [];
    return items.slice(0, 8).map((item) => {
      if (item.status === 'done') return '✓';
      if (item.status === 'planned' && item.todo_state === 'in_progress')
        return '●';
      if (item.status === 'deferred' || item.status === 'dropped') return '·';
      return '·';
    });
  });

  protected readonly topActivePlanItems = computed(() => {
    const items = this.vm()?.plan?.items ?? [];
    return items
      .filter(
        (it) =>
          it.status === 'planned' &&
          (it.todo_state === 'todo' || it.todo_state === 'in_progress'),
      )
      .slice(0, 2);
  });

  constructor() {
    // Topbar context is static for this page; no signal dependencies means
    // no need for effect() — a direct call mounts the context once.
    this.topbar.set({
      title: 'Today',
      crumbs: ['Commitment', 'Today'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected openJudgmentRow(row: JudgmentRow): void {
    if (row.route) this.router.navigate([row.route]);
  }

  protected planProgressPercent(done: number, total: number): number {
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
  }
}
