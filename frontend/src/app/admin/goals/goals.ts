import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Target,
  Loader2,
  RefreshCw,
} from 'lucide-angular';
import { GoalService } from '../../core/services/goal.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiGoal, GoalStatus } from '../../core/models';

type GroupBy = 'area' | 'quarter' | 'status';

interface GoalGroup {
  key: string;
  goals: ApiGoal[];
}

const STATUS_CONFIG: Record<GoalStatus, { label: string; classes: string }> = {
  'not-started': { label: 'Not Started', classes: 'border-zinc-600 bg-zinc-800 text-zinc-400' },
  'in-progress': { label: 'In Progress', classes: 'border-amber-800 bg-amber-900/30 text-amber-400' },
  done: { label: 'Done', classes: 'border-emerald-800 bg-emerald-900/30 text-emerald-400' },
  abandoned: { label: 'Abandoned', classes: 'border-red-800 bg-red-900/30 text-red-400' },
};

@Component({
  selector: 'app-goals',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './goals.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalsComponent implements OnInit {
  private readonly goalService = inject(GoalService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly goals = signal<ApiGoal[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly groupBy = signal<GroupBy>('area');

  protected readonly groupedGoals = computed<GoalGroup[]>(() => {
    const all = this.goals();
    const key = this.groupBy();
    const groups = new Map<string, ApiGoal[]>();

    for (const goal of all) {
      const groupKey = (goal[key] as string) || '(Unassigned)';
      const list = groups.get(groupKey) ?? [];
      list.push(goal);
      groups.set(groupKey, list);
    }

    return Array.from(groups.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, goals]) => ({ key: k, goals }));
  });

  protected readonly activeCounts = computed(() => {
    const all = this.goals();
    return {
      total: all.length,
      active: all.filter((g) => g.status === 'in-progress').length,
      done: all.filter((g) => g.status === 'done').length,
    };
  });

  // ─── Icons ───
  protected readonly TargetIcon = Target;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;

  ngOnInit(): void {
    this.loadGoals();
  }

  protected loadGoals(): void {
    this.isLoading.set(true);
    this.goalService
      .list()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.goals.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入目標');
          this.isLoading.set(false);
        },
      });
  }

  protected setGroupBy(g: GroupBy): void {
    this.groupBy.set(g);
  }

  protected getStatusLabel(status: GoalStatus): string {
    return STATUS_CONFIG[status].label;
  }

  protected getStatusClass(status: GoalStatus): string {
    return STATUS_CONFIG[status].classes;
  }

  protected isOverdue(goal: ApiGoal): boolean {
    if (!goal.deadline || goal.status === 'done' || goal.status === 'abandoned') {
      return false;
    }
    return new Date(goal.deadline) < new Date();
  }
}
