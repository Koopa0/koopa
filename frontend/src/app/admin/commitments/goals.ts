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
import {
  LucideAngularModule,
  Target,
  ChevronRight,
  Calendar,
} from 'lucide-angular';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import { InspectorService } from '../inspector/inspector.service';
import type { GoalsOverview, GoalSummary } from '../../core/models/admin.model';

@Component({
  selector: 'app-goals',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './goals.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalsComponent implements OnInit {
  private readonly planService = inject(PlanService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly inspector = inject(InspectorService);

  protected readonly overview = signal<GoalsOverview | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly areas = computed(() => this.overview()?.by_area ?? []);
  protected readonly totalGoals = computed(() =>
    this.areas().reduce((sum, area) => sum + area.goals.length, 0),
  );

  // Icons
  protected readonly TargetIcon = Target;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly CalendarIcon = Calendar;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    'not-started': 'text-zinc-500 bg-zinc-800/50 border-zinc-700/50',
    'in-progress': 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    'on-hold': 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    done: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    abandoned: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  ngOnInit(): void {
    this.loadOverview();
  }

  private loadOverview(): void {
    this.isLoading.set(true);
    this.planService
      .getGoalsOverview()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.overview.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load goals');
        },
      });
  }

  protected getMilestoneProgress(goal: GoalSummary): number {
    if (goal.milestones_total === 0) return 0;
    return Math.round((goal.milestones_done / goal.milestones_total) * 100);
  }

  protected getDeadlineUrgency(daysRemaining: number | null): string {
    if (daysRemaining === null) return 'text-zinc-500';
    if (daysRemaining < 7) return 'text-red-400';
    if (daysRemaining < 30) return 'text-amber-400';
    return 'text-zinc-400';
  }

  protected getGoalHealthBorder(goal: GoalSummary): string {
    const progress = this.getMilestoneProgress(goal);
    if (
      goal.days_remaining !== null &&
      goal.days_remaining < 14 &&
      progress < 50
    ) {
      return 'border-red-500/30 hover:border-red-500/50';
    }
    if (
      goal.days_remaining !== null &&
      goal.days_remaining < 30 &&
      progress < 30
    ) {
      return 'border-amber-500/30 hover:border-amber-500/50';
    }
    return 'border-zinc-800 hover:border-zinc-700';
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }

  /**
   * Plain click → open Inspector (no detail-route navigation).
   * Modifier click (cmd/ctrl/shift/middle) → fall through to the
   * existing routerLink so the goal detail page opens in a new tab.
   * The legacy detail route stays mounted in Phase 0 as a safety net.
   */
  protected onRowClick(event: MouseEvent, goal: GoalSummary): void {
    if (
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey ||
      event.button !== 0
    ) {
      return;
    }
    event.preventDefault();
    this.inspector.open({ type: 'goal', id: goal.id });
  }
}
