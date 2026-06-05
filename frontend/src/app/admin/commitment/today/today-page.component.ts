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
 * Today — the Commitment landing page. Three stacked regions:
 *
 *   HERO     — content in review + unverified hypotheses + completed
 *              tasks awaiting human approval. Hidden when empty; PLAN
 *              promotes to the top.
 *   PLAN     — today's daily_plan_items with status glyphs and the
 *              top two active items for quick context.
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
  protected readonly hasWarnings = computed(
    () => (this.vm()?.warnings ?? []).length > 0,
  );

  // Glyphs + active-item filtering derive only from the daily_plan_items
  // lifecycle (`status`, mapped from the backend `state`). The earlier
  // `todo_state` ('in_progress') branch was removed: the daily-plan endpoint
  // does not emit a todo GTD state, so that branch never fired in production
  // (see TodayService.BackendDailyPlanItem / Track 1B-correction).
  protected readonly planGlyphs = computed(() => {
    const items = this.vm()?.plan?.items ?? [];
    return items.slice(0, 8).map((item) => (item.status === 'done' ? '✓' : '·'));
  });

  protected readonly topActivePlanItems = computed(() => {
    const items = this.vm()?.plan?.items ?? [];
    return items.filter((it) => it.status === 'planned').slice(0, 2);
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
