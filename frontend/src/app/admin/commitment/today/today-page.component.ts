import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  TodayService,
  type PendingDetail,
  type TodayBrief,
} from './today.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

/** A labelled group of loose (unplanned) todos for the combined panel. */
interface LooseGroup {
  label: string;
  items: PendingDetail[];
}

/**
 * Today — the Daily landing page, bound to the brief(morning) aggregate
 * (GET /api/admin/commitment/today). It renders the day in skimmable,
 * independently-degrading sections: plan completion, the committed plan,
 * loose todos grouped overdue/today/upcoming, active goals, unverified
 * hypotheses, the active learning session (the one "now" accent), and RSS
 * highlights. Every list is always present ([]); the session is omitted
 * when none is open.
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
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<TodayBrief, void>({
    stream: () => this.todayService.today(),
  });

  protected readonly vm = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.vm(),
  );
  protected readonly isError = computed(
    () => this.resource.status() === 'error',
  );

  /** Overdue / today / upcoming loose todos, only the non-empty buckets. */
  protected readonly looseGroups = computed<LooseGroup[]>(() => {
    const v = this.vm();
    if (!v) return [];
    return [
      { label: 'Overdue', items: v.overdue_todos },
      { label: 'Due today', items: v.today_todos },
      { label: 'Upcoming', items: v.upcoming_todos },
    ].filter((g) => g.items.length > 0);
  });

  protected readonly hasLooseTodos = computed(
    () => this.looseGroups().length > 0,
  );

  /** committed.completed / total of the day's plan, as a percentage. */
  protected readonly planPercent = computed(() => {
    const pc = this.vm()?.plan_completion;
    if (!pc) return 0;
    const total = pc.planned + pc.completed + pc.deferred;
    return total === 0 ? 0 : Math.round((pc.completed / total) * 100);
  });

  /** True when every section is empty — drives the teaching empty state. */
  protected readonly isQuiet = computed(() => {
    const v = this.vm();
    if (!v) return false;
    return (
      v.committed_todos.length === 0 &&
      v.overdue_todos.length === 0 &&
      v.today_todos.length === 0 &&
      v.upcoming_todos.length === 0 &&
      v.active_goals.length === 0 &&
      v.unverified_hypotheses.length === 0 &&
      v.rss_highlights.length === 0 &&
      !v.active_session
    );
  });

  constructor() {
    this.topbar.set({ title: 'Today', crumbs: ['Daily', 'Today'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected goalPercent(done: number, total: number): number {
    if (total <= 0) return 0;
    return Math.round((done / total) * 100);
  }

  protected retry(): void {
    this.resource.reload();
  }
}
