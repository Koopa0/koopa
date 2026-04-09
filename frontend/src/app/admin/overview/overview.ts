import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { forkJoin } from 'rxjs';
import {
  LucideAngularModule,
  Sun,
  AlertTriangle,
  Inbox,
  Target,
  ArrowRight,
  Check,
  Clock,
  Zap,
  ChevronRight,
  Brain,
  TrendingUp,
  TrendingDown,
  Minus,
  FileText,
  Users,
  RotateCcw,
  Rss,
} from 'lucide-angular';
import { TodayService } from '../../core/services/today.service';
import { DashboardService } from '../../core/services/dashboard.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  MyDayContext,
  DashboardTrends,
  GoalPulse,
  DailyPlanItem,
} from '../../core/models/admin.model';

@Component({
  selector: 'app-overview',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './overview.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OverviewComponent implements OnInit {
  private readonly todayService = inject(TodayService);
  private readonly dashboardService = inject(DashboardService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = signal<MyDayContext | null>(null);
  protected readonly trends = signal<DashboardTrends | null>(null);
  protected readonly isLoading = signal(true);

  // --- Derived state from MyDayContext ---
  protected readonly todayDate = computed(() => this.context()?.date ?? '');
  protected readonly contextLine = computed(
    () => this.context()?.context_line ?? '',
  );
  protected readonly yesterdayUnfinished = computed(
    () => this.context()?.yesterday_unfinished ?? [],
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

  protected readonly planDoneCount = computed(
    () => this.todayPlan().filter((i) => i.status === 'done').length,
  );
  protected readonly planTotalCount = computed(() => this.todayPlan().length);

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

  // --- Derived state from DashboardTrends ---
  protected readonly executionTrend = computed(
    () => this.trends()?.execution ?? null,
  );
  protected readonly planAdherence = computed(
    () => this.trends()?.plan_adherence ?? null,
  );
  protected readonly goalHealth = computed(
    () => this.trends()?.goal_health ?? null,
  );
  protected readonly learningTrends = computed(
    () => this.trends()?.learning ?? null,
  );
  protected readonly contentTrends = computed(
    () => this.trends()?.content ?? null,
  );

  // Constant maps
  protected readonly ENERGY_LABELS: Record<string, string | undefined> = {
    high: 'H',
    medium: 'M',
    low: 'L',
  };

  protected readonly ENERGY_COLORS: Record<string, string | undefined> = {
    high: 'text-red-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
  };

  // Icons
  protected readonly SunIcon = Sun;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly InboxIcon = Inbox;
  protected readonly TargetIcon = Target;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly CheckIcon = Check;
  protected readonly ClockIcon = Clock;
  protected readonly ZapIcon = Zap;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly BrainIcon = Brain;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly TrendingDownIcon = TrendingDown;
  protected readonly MinusIcon = Minus;
  protected readonly FileTextIcon = FileText;
  protected readonly UsersIcon = Users;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly RssIcon = Rss;

  ngOnInit(): void {
    this.loadData();
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
          this.notificationService.error('Failed to load overview');
        },
      });
  }

  protected getMilestoneProgress(goal: GoalPulse): number {
    if (goal.milestones_total === 0) return 0;
    return Math.round((goal.milestones_done / goal.milestones_total) * 100);
  }

  protected getDeadlineUrgency(daysRemaining: number | null): string {
    if (daysRemaining === null) return 'text-zinc-500';
    if (daysRemaining < 7) return 'text-red-400';
    if (daysRemaining < 30) return 'text-amber-400';
    return 'text-zinc-400';
  }

  protected getGoalHealthColor(goal: GoalPulse): string {
    const progress = this.getMilestoneProgress(goal);
    if (
      goal.days_remaining !== null &&
      goal.days_remaining < 14 &&
      progress < 50
    ) {
      return 'border-red-500/30 bg-red-950/20';
    }
    if (
      goal.days_remaining !== null &&
      goal.days_remaining < 30 &&
      progress < 30
    ) {
      return 'border-amber-500/30 bg-amber-950/20';
    }
    return 'border-zinc-800 bg-zinc-900/50';
  }

  protected getPlanItemStatusClass(item: DailyPlanItem): string {
    switch (item.status) {
      case 'done':
        return 'line-through text-zinc-600';
      case 'deferred':
        return 'text-amber-500/70';
      case 'dropped':
        return 'line-through text-zinc-700';
      default:
        return 'text-zinc-300';
    }
  }

  protected getAttentionColor(count: number): string {
    if (count === 0) return 'text-zinc-600';
    if (count >= 5) return 'text-red-400';
    if (count >= 2) return 'text-amber-400';
    return 'text-zinc-300';
  }

  protected getTrendIcon(
    trend: string,
  ): typeof TrendingUp | typeof TrendingDown | typeof Minus {
    if (trend === 'up') return this.TrendingUpIcon;
    if (trend === 'down') return this.TrendingDownIcon;
    return this.MinusIcon;
  }

  protected getTrendColor(trend: string): string {
    if (trend === 'up') return 'text-emerald-400';
    if (trend === 'down') return 'text-red-400';
    return 'text-zinc-500';
  }
}
