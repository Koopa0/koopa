import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Brain,
  AlertTriangle,
  ChevronRight,
  RotateCcw,
  Trophy,
  Flame,
} from 'lucide-angular';
import { catchError, map, of, startWith } from 'rxjs';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  LearningDashboard,
  ConceptWeakness,
  DomainMastery,
} from '../../core/models/admin.model';

interface DashboardState {
  data: LearningDashboard | null;
  isLoading: boolean;
}

@Component({
  selector: 'app-weakness-map',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './weakness-map.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class WeaknessMapComponent {
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);

  private readonly state = toSignal(
    this.learnService.getDashboard().pipe(
      map((data): DashboardState => ({ data, isLoading: false })),
      catchError(() => {
        this.notificationService.error('Failed to load learning data');
        return of<DashboardState>({ data: null, isLoading: false });
      }),
      startWith<DashboardState>({ data: null, isLoading: true }),
    ),
    { requireSync: true },
  );

  protected readonly isLoading = computed(() => this.state().isLoading);
  protected readonly selectedDomain = signal<string | null>(null);

  // Derived
  protected readonly weaknesses = computed(() => {
    const all = this.state().data?.weakness_spotlight ?? [];
    const domain = this.selectedDomain();
    if (!domain) return all;
    return all.filter((w) => w.domain === domain);
  });

  protected readonly masteryByDomain = computed(
    () => this.state().data?.mastery_by_domain ?? [],
  );

  protected readonly dueReviewsCount = computed(
    () => this.state().data?.due_reviews_count ?? 0,
  );

  protected readonly dueReviewsToday = computed(
    () => this.state().data?.due_reviews_today ?? 0,
  );

  protected readonly streak = computed(
    () => this.state().data?.streak ?? { current_days: 0 },
  );

  protected readonly recentSessions = computed(
    () => this.state().data?.recent_sessions ?? [],
  );

  // Icons
  protected readonly BrainIcon = Brain;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly TrophyIcon = Trophy;
  protected readonly FlameIcon = Flame;

  // Color maps
  protected readonly DOMAIN_COLORS: Record<string, string | undefined> = {
    leetcode: 'bg-violet-900/40 text-violet-400 border-violet-800/50',
    japanese: 'bg-sky-900/40 text-sky-400 border-sky-800/50',
    'system-design': 'bg-emerald-900/40 text-emerald-400 border-emerald-800/50',
    go: 'bg-amber-900/40 text-amber-400 border-amber-800/50',
  };

  protected selectDomain(domain: string | null): void {
    this.selectedDomain.set(domain);
  }

  protected getMasteryPercent(domain: DomainMastery): number {
    if (domain.concepts_total === 0) return 0;
    return Math.round((domain.concepts_mastered / domain.concepts_total) * 100);
  }

  protected getWeaknessUrgency(weakness: ConceptWeakness): string {
    if (weakness.days_since_practice === null) return 'border-zinc-800';
    if (weakness.days_since_practice > 14) return 'border-red-800/40';
    if (weakness.days_since_practice > 7) return 'border-amber-800/40';
    return 'border-zinc-800';
  }

  protected getDomainColor(domain: string): string {
    return (
      this.DOMAIN_COLORS[domain] ??
      'bg-zinc-800/40 text-zinc-400 border-zinc-700/50'
    );
  }

  protected formatDaysSince(days: number | null): string {
    if (days === null) return 'Never practiced';
    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    return `${days}d ago`;
  }
}
