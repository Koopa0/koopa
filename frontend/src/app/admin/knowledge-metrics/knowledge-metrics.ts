import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  type OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LucideAngularModule, BookOpen, Loader2, TrendingUp, TrendingDown, Minus } from 'lucide-angular';
import { forkJoin } from 'rxjs';
import {
  LearningAnalyticsService,
  type CoverageMatrixResponse,
  type CoverageMatrixTopic,
  type TagSummaryResponse,
  type TagSummaryTag,
  type WeaknessTrendResponse,
} from '../../core/services/learning-analytics.service';
import { ProjectService } from '../../core/services/project/project.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiProject } from '../../core/models';

const FRESHNESS_DAYS = 7;
const STALE_DAYS = 14;
const DEPTH_THRESHOLD = 3;

@Component({
  selector: 'app-knowledge-metrics',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './knowledge-metrics.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KnowledgeMetricsComponent implements OnInit {
  private readonly analyticsService = inject(LearningAnalyticsService);
  private readonly projectService = inject(ProjectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly BookOpenIcon = BookOpen;
  protected readonly Loader2Icon = Loader2;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly TrendingDownIcon = TrendingDown;
  protected readonly MinusIcon = Minus;

  // ─── State ───
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly selectedProject = signal<string | null>(null);
  protected readonly coverageData = signal<CoverageMatrixResponse | null>(null);
  protected readonly weaknessData = signal<TagSummaryResponse | null>(null);
  protected readonly expandedWeakness = signal<string | null>(null);
  protected readonly weaknessTrend = signal<WeaknessTrendResponse | null>(null);
  protected readonly isLoading = signal(true);

  // ─── Derived: Coverage ───
  protected readonly sortedTopics = computed(() => {
    const data = this.coverageData();
    if (!data) return [];
    return [...data.topics].sort((a, b) => b.count - a.count);
  });

  protected readonly maxWeaknessCount = computed(() => {
    const data = this.weaknessData();
    if (!data || data.tags.length === 0) return 1;
    return Math.max(...data.tags.map((t) => t.count));
  });

  // ─── Helpers: Coverage tile styling ───

  protected tileBgClass(topic: CoverageMatrixTopic): string {
    if (topic.count === 0) return 'bg-zinc-800/50 border-zinc-700';
    if (topic.count < DEPTH_THRESHOLD) return 'bg-emerald-900/20 border-emerald-800';
    return 'bg-emerald-900/40 border-emerald-700';
  }

  protected tileBorderStyle(topic: CoverageMatrixTopic): string {
    const daysSince = this.daysSinceDate(topic.last_date);
    if (daysSince <= FRESHNESS_DAYS) return 'border-solid';
    if (daysSince >= STALE_DAYS) return 'border-dashed opacity-60';
    return 'border-solid';
  }

  protected acIndependentRatio(topic: CoverageMatrixTopic): number {
    if (topic.count === 0) return 0;
    return Math.round((topic.results['ac-independent'] / topic.count) * 100);
  }

  protected formatDate(dateStr: string): string {
    if (!dateStr) return '—';
    const parts = dateStr.split('-');
    if (parts.length < 3) return dateStr;
    return `${parts[1]}/${parts[2]}`;
  }

  // ─── Helpers: Weakness bar ───

  protected barWidthPercent(tag: TagSummaryTag): number {
    const max = this.maxWeaknessCount();
    return Math.round((tag.count / max) * 100);
  }

  protected trendIndicator(trend: string): string {
    switch (trend) {
      case 'improving': return '\u2191';
      case 'declining': return '\u2193';
      case 'stable': return '\u2192';
      default: return '?';
    }
  }

  protected trendColorClass(trend: string): string {
    switch (trend) {
      case 'improving': return 'text-emerald-400';
      case 'declining': return 'text-red-400';
      case 'stable': return 'text-amber-400';
      default: return 'text-zinc-500';
    }
  }

  protected occurrenceColor(result: string): string {
    switch (result) {
      case 'ac-independent': return 'bg-emerald-500';
      case 'ac-with-hints': return 'bg-amber-500';
      case 'ac-after-solution': return 'bg-red-500';
      default: return 'bg-zinc-500';
    }
  }

  protected formatWeaknessTag(tag: string): string {
    return tag.replace('weakness:', '');
  }

  // ─── Actions ───

  protected toggleWeakness(tag: string): void {
    if (this.expandedWeakness() === tag) {
      this.expandedWeakness.set(null);
      this.weaknessTrend.set(null);
      return;
    }

    this.expandedWeakness.set(tag);
    this.weaknessTrend.set(null);

    this.analyticsService
      .getWeaknessTrend(this.selectedProject()!, tag)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (trend) => this.weaknessTrend.set(trend),
        error: () => this.notificationService.error('無法載入趨勢資料'),
      });
  }

  // ─── Lifecycle ───

  protected selectProject(slug: string): void {
    this.selectedProject.set(slug);
    this.coverageData.set(null);
    this.weaknessData.set(null);
    this.expandedWeakness.set(null);
    this.weaknessTrend.set(null);
    this.isLoading.set(true);
    this.loadAnalytics(slug);
  }

  ngOnInit(): void {
    this.projectService
      .getAdminProjects()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (projects) => {
          this.projects.set(projects);
          if (projects.length > 0) {
            this.selectedProject.set(projects[0].slug);
            this.loadAnalytics(projects[0].slug);
          } else {
            this.isLoading.set(false);
          }
        },
        error: () => {
          this.notificationService.error('無法載入專案列表');
          this.isLoading.set(false);
        },
      });
  }

  private loadAnalytics(project: string): void {
    forkJoin({
      coverage: this.analyticsService.getCoverageMatrix(project),
      weakness: this.analyticsService.getTagSummary(project, 'weakness:'),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ coverage, weakness }) => {
          this.coverageData.set(coverage);
          this.weaknessData.set(weakness);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入分析資料');
          this.isLoading.set(false);
        },
      });
  }

  private daysSinceDate(dateStr: string): number {
    if (!dateStr) return 999;
    const target = new Date(dateStr + 'T00:00:00');
    const now = new Date();
    const diffMs = now.getTime() - target.getTime();
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  }
}
