import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';
import { TodayService } from '../../core/services/today.service';
import { DashboardService } from '../../core/services/dashboard.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  DashboardTrends,
  MyDayContext,
} from '../../core/models/admin.model';

/**
 * NOW mode — 3-column situational awareness workspace.
 *
 *   Left   (Attention):  needs_attention counts + overdue tasks
 *   Center (Today):      today plan + goal pulse (clickable to inspector)
 *   Right  (Ambient):    weekly trends (execution, adherence, learning, content)
 *
 * Phase 1 baseline. Day 11 will pass an a11y polish on this. Day 12 will
 * delete the legacy /admin/overview page that this fully replaces.
 */
@Component({
  selector: 'app-now-page',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './now-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NowPageComponent implements OnInit {
  private readonly todayService = inject(TodayService);
  private readonly dashboardService = inject(DashboardService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = signal<MyDayContext | null>(null);
  protected readonly trends = signal<DashboardTrends | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly todayDate = computed(() => this.context()?.date ?? '');
  protected readonly contextLine = computed(
    () => this.context()?.context_line ?? '',
  );
  protected readonly todayPlan = computed(
    () => this.context()?.today_plan ?? [],
  );
  protected readonly goalPulse = computed(
    () => this.context()?.goal_pulse ?? [],
  );
  protected readonly attention = computed(
    () => this.context()?.needs_attention ?? null,
  );
  protected readonly overdueTasks = computed(
    () => this.context()?.overdue_tasks ?? [],
  );
  protected readonly yesterdayUnfinished = computed(
    () => this.context()?.yesterday_unfinished ?? [],
  );

  protected readonly planDoneCount = computed(
    () => this.todayPlan().filter((p) => p.status === 'done').length,
  );

  protected readonly hasAttentionItems = computed(() => {
    const a = this.attention();
    if (!a) return false;
    return (
      a.inbox_count > 0 ||
      a.pending_directives > 0 ||
      a.due_reviews > 0 ||
      a.overdue_tasks > 0
    );
  });

  protected readonly executionTrend = computed(
    () => this.trends()?.execution ?? null,
  );
  protected readonly planAdherence = computed(
    () => this.trends()?.plan_adherence ?? null,
  );
  protected readonly goalHealthTrend = computed(
    () => this.trends()?.goal_health ?? null,
  );
  protected readonly learningTrends = computed(
    () => this.trends()?.learning ?? null,
  );
  protected readonly contentTrends = computed(
    () => this.trends()?.content ?? null,
  );

  ngOnInit(): void {
    this.loadData();
  }

  protected getDeadlineUrgency(daysRemaining: number | null): string {
    if (daysRemaining === null) return 'text-zinc-500';
    if (daysRemaining < 7) return 'text-red-400';
    if (daysRemaining < 30) return 'text-amber-400';
    return 'text-zinc-400';
  }

  protected getEnergyLabel(energy: string): string {
    return energy.charAt(0).toUpperCase();
  }

  protected getEnergyColor(energy: string): string {
    switch (energy) {
      case 'high':
        return 'text-red-400';
      case 'medium':
        return 'text-amber-400';
      case 'low':
        return 'text-emerald-400';
      default:
        return 'text-zinc-500';
    }
  }

  private loadData(): void {
    this.isLoading.set(true);
    forkJoin({
      context: this.todayService.getMyDayContext(),
      trends: this.dashboardService.getDashboardTrends(),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ context, trends }) => {
          this.context.set(context);
          this.trends.set(trends);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load NOW context');
        },
      });
  }
}
