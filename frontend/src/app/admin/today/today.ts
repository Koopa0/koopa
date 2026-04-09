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
import {
  LucideAngularModule,
  Sun,
  AlertTriangle,
  Inbox,
  FileText,
  BookOpen,
  Target,
  ArrowRight,
  Check,
  RotateCcw,
  X,
  Clock,
  Zap,
  ChevronRight,
  Play,
} from 'lucide-angular';
import { TodayService } from '../../core/services/today.service';
import { NotificationService } from '../../core/services/notification.service';
import type { MyDayContext, GoalPulse } from '../../core/models/admin.model';

@Component({
  selector: 'app-today',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './today.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodayComponent implements OnInit {
  private readonly todayService = inject(TodayService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = signal<MyDayContext | null>(null);
  protected readonly isLoading = signal(true);

  // Derived state
  protected readonly yesterdayUnfinished = computed(
    () => this.context()?.yesterday_unfinished ?? [],
  );
  protected readonly todayPlan = computed(
    () => this.context()?.today_plan ?? [],
  );
  protected readonly overdueTasks = computed(
    () => this.context()?.overdue_tasks ?? [],
  );
  protected readonly needsAttention = computed(
    () => this.context()?.needs_attention ?? null,
  );
  protected readonly goalPulse = computed(
    () => this.context()?.goal_pulse ?? [],
  );
  protected readonly contextLine = computed(
    () => this.context()?.context_line ?? '',
  );
  protected readonly todayDate = computed(() => this.context()?.date ?? '');

  protected readonly hasOverdue = computed(
    () => this.overdueTasks().length > 0,
  );
  protected readonly hasUnfinished = computed(
    () => this.yesterdayUnfinished().length > 0,
  );
  protected readonly totalAttention = computed(() => {
    const n = this.needsAttention();
    if (!n) return 0;
    return (
      n.inbox_count +
      n.pending_directives +
      n.unread_reports +
      n.due_reviews +
      n.overdue_tasks +
      n.stale_someday_count
    );
  });
  protected readonly totalPlannedMinutes = computed(() =>
    this.todayPlan().reduce(
      (sum, item) => sum + (item.estimated_minutes ?? 0),
      0,
    ),
  );

  // Constant maps — avoid method calls in template @for loops
  protected readonly ENERGY_LABELS: Record<string, string> = {
    high: 'H',
    medium: 'M',
    low: 'L',
  };

  protected readonly ENERGY_COLORS: Record<string, string> = {
    high: 'text-red-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
  };

  // Full class strings — Tailwind JIT cannot parse dynamically concatenated classes
  protected readonly AREA_CLASSES: Record<string, string> = {
    backend: 'bg-violet-900/40 text-violet-400',
    learning: 'bg-sky-900/40 text-sky-400',
    studio: 'bg-amber-900/40 text-amber-400',
    career: 'bg-emerald-900/40 text-emerald-400',
    frontend: 'bg-blue-900/40 text-blue-400',
    ops: 'bg-orange-900/40 text-orange-400',
  };

  // Lucide icons
  protected readonly SunIcon = Sun;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly InboxIcon = Inbox;
  protected readonly FileTextIcon = FileText;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly TargetIcon = Target;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly CheckIcon = Check;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly XIcon = X;
  protected readonly ClockIcon = Clock;
  protected readonly ZapIcon = Zap;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly PlayIcon = Play;

  ngOnInit(): void {
    this.loadContext();
  }

  private loadContext(): void {
    this.isLoading.set(true);
    this.todayService
      .getMyDayContext()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.context.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load today context');
        },
      });
  }

  protected resolveItem(
    itemId: string,
    action: 'complete' | 'defer' | 'drop',
  ): void {
    this.todayService
      .resolveDailyItem(itemId, action)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          // Update state locally
          this.context.update((ctx) => {
            if (!ctx) return ctx;
            return {
              ...ctx,
              yesterday_unfinished: ctx.yesterday_unfinished.filter(
                (i) => i.id !== itemId,
              ),
              today_plan:
                action === 'complete' ? ctx.today_plan : ctx.today_plan,
            };
          });
        },
        error: () => this.notificationService.error('Operation failed'),
      });
  }

  protected resolvePlanItem(itemId: string, action: 'defer' | 'drop'): void {
    this.todayService
      .resolveDailyItem(itemId, action)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.context.update((ctx) => {
            if (!ctx) return ctx;
            return {
              ...ctx,
              today_plan: ctx.today_plan.filter((i) => i.id !== itemId),
            };
          });
        },
        error: () => this.notificationService.error('Operation failed'),
      });
  }

  protected completePlanItem(itemId: string): void {
    this.todayService
      .resolveDailyItem(itemId, 'complete')
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.context.update((ctx) => {
            if (!ctx) return ctx;
            return {
              ...ctx,
              today_plan: ctx.today_plan.map((i) =>
                i.id === itemId ? { ...i, status: 'done' as const } : i,
              ),
            };
          });
        },
        error: () => this.notificationService.error('Operation failed'),
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
}
