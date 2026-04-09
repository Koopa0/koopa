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
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Target,
  Check,
  Circle,
  FolderOpen,
} from 'lucide-angular';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import type { GoalDetail } from '../../core/models/admin.model';

@Component({
  selector: 'app-goal-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './goal-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly planService = inject(PlanService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly goal = signal<GoalDetail | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly milestones = computed(() => this.goal()?.milestones ?? []);
  protected readonly projects = computed(() => this.goal()?.projects ?? []);
  protected readonly recentActivity = computed(
    () => this.goal()?.recent_activity ?? [],
  );

  protected readonly milestoneProgress = computed(() => {
    const ms = this.milestones();
    if (ms.length === 0) return { done: 0, total: 0, percent: 0 };
    const done = ms.filter((m) => m.completed).length;
    return {
      done,
      total: ms.length,
      percent: Math.round((done / ms.length) * 100),
    };
  });

  // Icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly TargetIcon = Target;
  protected readonly CheckIcon = Check;
  protected readonly CircleIcon = Circle;
  protected readonly FolderOpenIcon = FolderOpen;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    'not-started': 'text-zinc-500 bg-zinc-800/50 border-zinc-700/50',
    'in-progress': 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    'on-hold': 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    done: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    abandoned: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  protected readonly HEALTH_COLORS: Record<string, string | undefined> = {
    'on-track': 'text-emerald-400',
    'at-risk': 'text-amber-400',
    stalled: 'text-red-400',
  };

  protected readonly PROJECT_STATUS_COLORS: Record<string, string | undefined> =
    {
      planned: 'text-zinc-400',
      'in-progress': 'text-sky-400',
      'on-hold': 'text-amber-400',
      completed: 'text-emerald-400',
      maintained: 'text-blue-400',
      archived: 'text-zinc-600',
    };

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.loadGoal(id);
    }
  }

  private loadGoal(id: string): void {
    this.isLoading.set(true);
    this.planService
      .getGoalDetail(id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.goal.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load goal');
        },
      });
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }

  protected getHealthColor(health: string): string {
    return this.HEALTH_COLORS[health] ?? 'text-zinc-500';
  }

  protected getProjectStatusColor(status: string): string {
    return this.PROJECT_STATUS_COLORS[status] ?? 'text-zinc-500';
  }

  protected getDeadlineDays(deadline: string | null): number | null {
    if (!deadline) return null;
    const target = new Date(deadline);
    const now = new Date();
    return Math.ceil(
      (target.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );
  }
}
