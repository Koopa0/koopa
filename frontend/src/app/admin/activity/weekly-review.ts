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
import { ActivatedRoute, Router } from '@angular/router';
import {
  LucideAngularModule,
  Target,
  FolderKanban,
  BookOpen,
  FileText,
  Inbox,
  Lightbulb,
  BarChart3,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  GitCommit,
  Hammer,
  ChevronLeft,
  ChevronRight,
} from 'lucide-angular';
import { ReflectService } from '../../core/services/reflect.service';
import { NotificationService } from '../../core/services/notification.service';
import type { WeeklyReviewContext } from '../../core/models/admin.model';

@Component({
  selector: 'app-weekly-review',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './weekly-review.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class WeeklyReviewComponent implements OnInit {
  private readonly reflectService = inject(ReflectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  protected readonly context = signal<WeeklyReviewContext | null>(null);
  protected readonly isLoading = signal(true);

  // Derived state
  protected readonly goalProgress = computed(
    () => this.context()?.goal_progress ?? [],
  );
  protected readonly projectHealth = computed(
    () => this.context()?.project_health ?? [],
  );
  protected readonly learningSummary = computed(
    () => this.context()?.learning_summary ?? null,
  );
  protected readonly contentOutput = computed(
    () => this.context()?.content_output ?? null,
  );
  protected readonly inboxHealth = computed(
    () => this.context()?.inbox_health ?? null,
  );
  protected readonly insightsNeedingCheck = computed(
    () => this.context()?.insights_needing_check ?? [],
  );
  protected readonly metrics = computed(() => this.context()?.metrics ?? null);

  protected readonly weekRange = computed(() => {
    const ctx = this.context();
    if (!ctx) return '';
    return `${ctx.week_start} ~ ${ctx.week_end}`;
  });

  protected readonly inboxNetChange = computed(() => {
    const health = this.inboxHealth();
    if (!health) return 0;
    return health.end_count - health.start_count;
  });

  protected readonly isCurrentWeek = computed(() => {
    const ctx = this.context();
    if (!ctx) return true;
    const now = new Date();
    const weekEnd = new Date(ctx.week_end);
    return weekEnd >= now;
  });

  // Lucide icons
  protected readonly TargetIcon = Target;
  protected readonly FolderKanbanIcon = FolderKanban;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly FileTextIcon = FileText;
  protected readonly InboxIcon = Inbox;
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly BarChart3Icon = BarChart3;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly TrendingDownIcon = TrendingDown;
  protected readonly GitCommitIcon = GitCommit;
  protected readonly HammerIcon = Hammer;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;

  ngOnInit(): void {
    this.route.queryParamMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const weekStart = params.get('week_start') ?? undefined;
        this.loadContext(weekStart);
      });
  }

  private loadContext(weekStart?: string): void {
    this.isLoading.set(true);
    this.reflectService
      .getWeeklyContext(weekStart)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.context.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load weekly review');
        },
      });
  }

  protected navigateWeek(offset: number): void {
    const ctx = this.context();
    const base = ctx?.week_start ?? new Date().toISOString().slice(0, 10);
    const d = new Date(base);
    d.setDate(d.getDate() + offset * 7);
    const target = d.toISOString().slice(0, 10);
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { week_start: target },
      queryParamsHandling: 'merge',
    });
  }

  protected getMilestonePercent(done: number, total: number): number {
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
  }
}
