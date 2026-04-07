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
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Target,
  RefreshCw,
  ChevronUp,
} from 'lucide-angular';
import { GoalService } from '../../core/services/goal.service';
import { NotificationService } from '../../core/services/notification.service';
import {
  PageHeaderComponent,
  EmptyStateComponent,
  LoadingSpinnerComponent,
} from '../../shared/components';
import type { ApiGoal, GoalStatus } from '../../core/models';

type FilterTab = 'all' | 'active' | 'achieved' | 'abandoned';

interface GoalGroup {
  key: string;
  goals: ApiGoal[];
}

const STATUS_OPTIONS: { value: GoalStatus; label: string }[] = [
  { value: 'not-started', label: 'Not Started' },
  { value: 'in-progress', label: 'In Progress' },
  { value: 'done', label: 'Done' },
  { value: 'abandoned', label: 'Abandoned' },
];

const STATUS_CONFIG: Record<GoalStatus, { label: string; classes: string }> = {
  'not-started': {
    label: 'Not Started',
    classes: 'border-zinc-600 bg-zinc-800 text-zinc-400',
  },
  'in-progress': {
    label: 'In Progress',
    classes: 'border-amber-800 bg-amber-900/30 text-amber-400',
  },
  done: {
    label: 'Done',
    classes: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  },
  abandoned: {
    label: 'Abandoned',
    classes: 'border-red-800 bg-red-900/30 text-red-400',
  },
};

const FILTER_TABS: { value: FilterTab; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'active', label: 'Active' },
  { value: 'achieved', label: 'Achieved' },
  { value: 'abandoned', label: 'Abandoned' },
];

@Component({
  selector: 'app-goals',
  standalone: true,
  imports: [
    FormsModule,
    LucideAngularModule,
    PageHeaderComponent,
    EmptyStateComponent,
    LoadingSpinnerComponent,
  ],
  templateUrl: './goals.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalsComponent implements OnInit {
  private readonly goalService = inject(GoalService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly goals = signal<ApiGoal[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly activeTab = signal<FilterTab>('active');
  protected readonly expandedDescriptions = signal<Set<string>>(new Set());

  protected readonly filterTabs = FILTER_TABS;
  protected readonly statusOptions = STATUS_OPTIONS;

  protected readonly filteredGoals = computed<ApiGoal[]>(() => {
    const all = this.goals();
    const tab = this.activeTab();

    switch (tab) {
      case 'active':
        return all.filter(
          (g) => g.status === 'in-progress' || g.status === 'not-started',
        );
      case 'achieved':
        return all.filter((g) => g.status === 'done');
      case 'abandoned':
        return all.filter((g) => g.status === 'abandoned');
      default:
        return all;
    }
  });

  protected readonly groupedGoals = computed<GoalGroup[]>(() => {
    const filtered = this.filteredGoals();
    const groups = new Map<string, ApiGoal[]>();

    for (const goal of filtered) {
      const groupKey = goal.area || '(Unassigned)';
      const list = groups.get(groupKey) ?? [];
      list.push(goal);
      groups.set(groupKey, list);
    }

    return Array.from(groups.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, goals]) => ({ key: k, goals }));
  });

  protected readonly tabCounts = computed(() => {
    const all = this.goals();
    return {
      all: all.length,
      active: all.filter(
        (g) => g.status === 'in-progress' || g.status === 'not-started',
      ).length,
      achieved: all.filter((g) => g.status === 'done').length,
      abandoned: all.filter((g) => g.status === 'abandoned').length,
    };
  });

  // ─── Icons ───
  protected readonly TargetIcon = Target;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly ChevronUpIcon = ChevronUp;

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

  protected setTab(tab: FilterTab): void {
    this.activeTab.set(tab);
  }

  protected getTabCount(tab: FilterTab): number {
    return this.tabCounts()[tab];
  }

  protected updateStatus(goal: ApiGoal, newStatus: GoalStatus): void {
    if (newStatus === goal.status) return;

    const previousStatus = goal.status;
    // Optimistic update
    this.goals.update((goals) =>
      goals.map((g) => (g.id === goal.id ? { ...g, status: newStatus } : g)),
    );

    this.goalService
      .updateStatus(goal.id, newStatus)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success(`「${goal.title}」狀態已更新`);
        },
        error: () => {
          // Rollback
          this.goals.update((goals) =>
            goals.map((g) =>
              g.id === goal.id ? { ...g, status: previousStatus } : g,
            ),
          );
          this.notificationService.error('更新狀態失敗');
        },
      });
  }

  protected getStatusLabel(status: GoalStatus): string {
    return STATUS_CONFIG[status].label;
  }

  protected getStatusClass(status: GoalStatus): string {
    return STATUS_CONFIG[status].classes;
  }

  protected deadlineDays(goal: ApiGoal): number | null {
    if (
      !goal.deadline ||
      goal.status === 'done' ||
      goal.status === 'abandoned'
    ) {
      return null;
    }
    const deadline = new Date(goal.deadline + 'T00:00:00');
    const now = new Date(new Date().toISOString().slice(0, 10) + 'T00:00:00');
    const days = Math.floor((deadline.getTime() - now.getTime()) / 86400000);
    return Number.isNaN(days) ? null : days;
  }

  protected deadlineClass(goal: ApiGoal): string {
    const days = this.deadlineDays(goal);
    if (days === null) return 'text-zinc-500';
    if (days < 0) return 'text-red-400';
    if (days < 7) return 'text-red-400';
    if (days < 30) return 'text-amber-400';
    return 'text-zinc-500';
  }

  protected deadlineLabel(goal: ApiGoal): string {
    const days = this.deadlineDays(goal);
    if (days === null) return goal.deadline ?? '';
    if (days < 0) return `逾期 ${Math.abs(days)} 天`;
    if (days === 0) return '今日到期';
    return `${days} 天後到期`;
  }

  protected isDescriptionExpanded(goalId: string): boolean {
    return this.expandedDescriptions().has(goalId);
  }

  protected toggleDescription(goalId: string): void {
    this.expandedDescriptions.update((set) => {
      const next = new Set(set);
      if (next.has(goalId)) {
        next.delete(goalId);
      } else {
        next.add(goalId);
      }
      return next;
    });
  }

  protected formatDeadline(deadline: string): string {
    return deadline.slice(0, 10);
  }
}
