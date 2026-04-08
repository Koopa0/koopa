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
  Calendar,
  CheckCircle,
  Circle,
  FolderKanban,
  Activity,
  GitCommit,
  CheckSquare,
  FileText,
  ChevronDown,
  ChevronUp,
  ArrowRight,
} from 'lucide-angular';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import type { LucideIconData } from 'lucide-angular';
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
  protected readonly isDescriptionExpanded = signal(false);

  // 衍生狀態
  protected readonly milestones = computed(() => {
    const g = this.goal();
    if (!g) return [];
    return [...g.milestones].sort((a, b) => a.position - b.position);
  });

  protected readonly projects = computed(() => this.goal()?.projects ?? []);

  protected readonly recentActivity = computed(() => {
    const items = this.goal()?.recent_activity ?? [];
    return items.slice(0, 5);
  });

  protected readonly milestoneDoneCount = computed(
    () => this.milestones().filter((m) => m.completed).length,
  );

  protected readonly milestoneTotal = computed(() => this.milestones().length);

  protected readonly daysRemaining = computed(() => {
    const g = this.goal();
    if (!g?.deadline) return null;
    const deadline = new Date(g.deadline);
    const now = new Date();
    return Math.ceil(
      (deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );
  });

  protected readonly isDescriptionLong = computed(() => {
    const desc = this.goal()?.description ?? '';
    return desc.length > 120;
  });

  protected readonly displayDescription = computed(() => {
    const desc = this.goal()?.description ?? '';
    if (!this.isDescriptionLong() || this.isDescriptionExpanded()) return desc;
    return desc.slice(0, 120) + '...';
  });

  // 常量映射
  protected readonly STATUS_LABELS: Record<string, string> = {
    'not-started': '未開始',
    'in-progress': '進行中',
    done: '已完成',
    abandoned: '已放棄',
  };

  protected readonly STATUS_CLASSES: Record<string, string> = {
    'not-started': 'bg-zinc-800 text-zinc-400',
    'in-progress': 'bg-sky-900/40 text-sky-400',
    done: 'bg-emerald-900/40 text-emerald-400',
    abandoned: 'bg-red-900/40 text-red-400',
  };

  protected readonly HEALTH_LABELS: Record<string, string> = {
    'on-track': '正常',
    'at-risk': '有風險',
    stalled: '停滯',
  };

  protected readonly HEALTH_CLASSES: Record<string, string> = {
    'on-track': 'bg-emerald-900/40 text-emerald-400',
    'at-risk': 'bg-amber-900/40 text-amber-400',
    stalled: 'bg-red-900/40 text-red-400',
  };

  protected readonly PROJECT_STATUS_LABELS: Record<string, string> = {
    'in-progress': '進行中',
    'on-hold': '暫停',
    done: '已完成',
    'not-started': '未開始',
  };

  protected readonly PROJECT_STATUS_CLASSES: Record<string, string> = {
    'in-progress': 'bg-sky-900/40 text-sky-400',
    'on-hold': 'bg-amber-900/40 text-amber-400',
    done: 'bg-emerald-900/40 text-emerald-400',
    'not-started': 'bg-zinc-800 text-zinc-400',
  };

  protected readonly ACTIVITY_ICONS: Record<string, LucideIconData> = {
    task_completed: CheckSquare,
    commit: GitCommit,
    content: FileText,
  };

  // Lucide icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly TargetIcon = Target;
  protected readonly CalendarIcon = Calendar;
  protected readonly CheckCircleIcon = CheckCircle;
  protected readonly CircleIcon = Circle;
  protected readonly FolderKanbanIcon = FolderKanban;
  protected readonly ActivityIcon = Activity;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly ChevronUpIcon = ChevronUp;
  protected readonly ArrowRightIcon = ArrowRight;

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
          this.notificationService.error('無法載入目標詳情');
        },
      });
  }

  protected toggleDescription(): void {
    this.isDescriptionExpanded.update((v) => !v);
  }

  protected getDeadlineUrgency(days: number | null): string {
    if (days === null) return 'text-zinc-500';
    if (days < 0) return 'text-red-400';
    if (days < 7) return 'text-red-400';
    if (days < 30) return 'text-amber-400';
    return 'text-zinc-400';
  }

  protected getDeadlineLabel(days: number | null): string {
    if (days === null) return '';
    if (days < 0) return `已逾期 ${Math.abs(days)} 天`;
    if (days === 0) return '今天到期';
    return `剩餘 ${days} 天`;
  }

  protected getProjectProgress(total: number, done: number): number {
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
  }

  protected getActivityIcon(type: string): LucideIconData {
    return this.ACTIVITY_ICONS[type] ?? this.ActivityIcon;
  }
}
