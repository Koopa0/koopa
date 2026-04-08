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
  GraduationCap,
  AlertTriangle,
  Brain,
  Clock,
  Flame,
  Play,
  ChevronRight,
  RotateCcw,
  Trophy,
} from 'lucide-angular';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  LearningDashboard,
  SessionSummary,
  DomainMastery,
} from '../../core/models/admin.model';

@Component({
  selector: 'app-learn-dashboard',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './learn-dashboard.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LearnDashboardComponent implements OnInit {
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly dashboard = signal<LearningDashboard | null>(null);
  protected readonly isLoading = signal(true);

  // 衍生狀態
  protected readonly dueReviewsCount = computed(
    () => this.dashboard()?.due_reviews_count ?? 0,
  );
  protected readonly dueReviewsToday = computed(
    () => this.dashboard()?.due_reviews_today ?? 0,
  );
  protected readonly recentSessions = computed(
    () => this.dashboard()?.recent_sessions ?? [],
  );
  protected readonly weaknessSpotlight = computed(
    () => this.dashboard()?.weakness_spotlight ?? [],
  );
  protected readonly masteryByDomain = computed(
    () => this.dashboard()?.mastery_by_domain ?? [],
  );
  protected readonly streak = computed(
    () => this.dashboard()?.streak ?? { current_days: 0, longest: 0 },
  );

  protected readonly hasDueReviews = computed(() => this.dueReviewsCount() > 0);

  // 常量映射
  protected readonly DOMAIN_COLORS: Record<string, string> = {
    algorithms: 'text-violet-400',
    'system-design': 'text-sky-400',
    'go-patterns': 'text-emerald-400',
    database: 'text-amber-400',
  };

  protected readonly DOMAIN_BG: Record<string, string> = {
    algorithms: 'bg-violet-900/40 text-violet-400',
    'system-design': 'bg-sky-900/40 text-sky-400',
    'go-patterns': 'bg-emerald-900/40 text-emerald-400',
    database: 'bg-amber-900/40 text-amber-400',
  };

  // Lucide icons
  protected readonly GraduationCapIcon = GraduationCap;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly BrainIcon = Brain;
  protected readonly ClockIcon = Clock;
  protected readonly FlameIcon = Flame;
  protected readonly PlayIcon = Play;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly TrophyIcon = Trophy;

  ngOnInit(): void {
    this.loadDashboard();
  }

  private loadDashboard(): void {
    this.isLoading.set(true);
    this.learnService
      .getDashboard()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.dashboard.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('無法載入學習儀表板');
        },
      });
  }

  protected getMasteryPercent(domain: DomainMastery): number {
    if (domain.concepts_total === 0) return 0;
    return Math.round((domain.concepts_mastered / domain.concepts_total) * 100);
  }

  protected getSessionRatio(session: SessionSummary): string {
    return `${session.solved_count}/${session.attempts_count}`;
  }

  protected getDaysSinceClass(days: number | null): string {
    if (days === null) return 'text-zinc-500';
    if (days > 7) return 'text-red-400';
    if (days > 3) return 'text-amber-400';
    return 'text-zinc-400';
  }
}
