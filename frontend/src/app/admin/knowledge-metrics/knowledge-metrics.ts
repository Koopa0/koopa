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
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  BookOpen,
  Eye,
  Check,
  Loader2,
} from 'lucide-angular';
import { forkJoin } from 'rxjs';
import {
  LearningAnalyticsService,
  type CoverageMatrixResponse,
  type CoverageMatrixTopic,
  type TagSummaryResponse,
  type TagSummaryTag,
  type WeaknessTrendResponse,
  type LearningTimelineResult,
  type TimelineDay,
  type TimelineEntry,
  type RetrievalQuality,
} from '../../core/services/learning-analytics.service';
import { ProjectService } from '../../core/services/project/project.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiProject } from '../../core/models';

const FRESHNESS_DAYS = 7;
const STALE_DAYS = 14;
const DEPTH_THRESHOLD = 3;
const TIMELINE_DAYS = 14;

/** Content types that use slug-based detail routes */
const SLUG_ROUTE_TYPES = new Set(['til', 'note', 'build-log', 'bookmark']);

/** Route prefix for each content type */
const ROUTE_MAP: Record<string, string> = {
  til: '/til',
  note: '/notes',
  'build-log': '/build-logs',
  bookmark: '/bookmarks',
};

@Component({
  selector: 'app-knowledge-metrics',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './knowledge-metrics.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KnowledgeMetricsComponent implements OnInit {
  private readonly analyticsService = inject(LearningAnalyticsService);
  private readonly projectService = inject(ProjectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly BookOpenIcon = BookOpen;
  protected readonly EyeIcon = Eye;
  protected readonly CheckIcon = Check;
  protected readonly Loader2Icon = Loader2;

  // ─── State ───
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly selectedProject = signal<string | null>(null);
  protected readonly coverageData = signal<CoverageMatrixResponse | null>(null);
  protected readonly weaknessData = signal<TagSummaryResponse | null>(null);
  protected readonly timelineData = signal<LearningTimelineResult | null>(null);
  protected readonly expandedWeakness = signal<string | null>(null);
  protected readonly weaknessTrend = signal<WeaknessTrendResponse | null>(null);
  protected readonly isLoading = signal(true);

  // Self-test state
  protected readonly revealedObservations = signal<Set<string>>(new Set());
  protected readonly recordedAttempts = signal<Set<string>>(new Set());

  // ─── Derived: Summary Cards ───
  protected readonly activeDays = computed(() => {
    return this.timelineData()?.summary.active_days ?? 0;
  });

  protected readonly currentStreak = computed(() => {
    return this.timelineData()?.summary.current_streak ?? 0;
  });

  protected readonly acIndependentOverall = computed(() => {
    const timeline = this.timelineData();
    if (!timeline) return 0;
    const entries = timeline.days.flatMap((d) => d.entries);
    if (entries.length === 0) return 0;
    const acCount = entries.filter((e) => e.result === 'ac-independent').length;
    return Math.round((acCount / entries.length) * 100);
  });

  protected readonly activeWeaknessCount = computed(() => {
    return this.weaknessData()?.total_tags ?? 0;
  });

  // ─── Derived: Timeline ───
  protected readonly timelineDays = computed<TimelineDay[]>(() => {
    return this.timelineData()?.days ?? [];
  });

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

  // ─── Helpers: Content detail route ───

  protected contentDetailRoute(
    contentType: string,
    slug: string,
  ): string | null {
    if (!SLUG_ROUTE_TYPES.has(contentType)) return null;
    const prefix = ROUTE_MAP[contentType];
    return prefix ? `${prefix}/${slug}` : null;
  }

  // ─── Helpers: Timeline ───

  protected entryColorClass(entry: TimelineEntry): string {
    switch (entry.result) {
      case 'ac-independent':
        return 'border-emerald-700 bg-emerald-900/20 text-emerald-300';
      case 'ac-with-hints':
        return 'border-amber-700 bg-amber-900/20 text-amber-300';
      case 'ac-after-solution':
        return 'border-red-700 bg-red-900/20 text-red-300';
      case 'incomplete':
        return 'border-zinc-600 bg-zinc-800 text-zinc-400';
      default:
        return 'border-zinc-700 bg-zinc-800/50 text-zinc-300';
    }
  }

  // ─── Helpers: Coverage tile ───

  protected tileBgClass(topic: CoverageMatrixTopic): string {
    if (topic.count === 0) return 'bg-zinc-800/50 border-zinc-700';
    if (topic.count < DEPTH_THRESHOLD)
      return 'bg-emerald-900/20 border-emerald-800';
    return 'bg-emerald-900/40 border-emerald-700';
  }

  protected tileBorderStyle(topic: CoverageMatrixTopic): string {
    const daysSince = this.daysSinceDate(topic.last_date);
    if (daysSince <= FRESHNESS_DAYS) return 'border-solid';
    if (daysSince >= STALE_DAYS) return 'border-dashed opacity-60';
    return 'border-solid';
  }

  protected resultBlocks(
    topic: CoverageMatrixTopic,
  ): { type: string; key: number }[] {
    const blocks: { type: string; key: number }[] = [];
    let i = 0;
    for (const [type, count] of Object.entries(topic.results)) {
      for (let j = 0; j < count; j++) {
        blocks.push({ type, key: i++ });
      }
    }
    return blocks;
  }

  protected resultBlockClass(type: string): string {
    switch (type) {
      case 'ac-independent':
        return 'bg-emerald-500';
      case 'ac-with-hints':
        return 'bg-amber-500';
      case 'ac-after-solution':
        return 'bg-red-500';
      default:
        return 'bg-zinc-500';
    }
  }

  protected staleDays(topic: CoverageMatrixTopic): number | null {
    const days = this.daysSinceDate(topic.last_date);
    return days > STALE_DAYS ? days : null;
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
      case 'improving':
        return '\u2191';
      case 'declining':
        return '\u2193';
      case 'stable':
        return '\u2192';
      default:
        return '?';
    }
  }

  protected trendColorClass(trend: string): string {
    switch (trend) {
      case 'improving':
        return 'text-emerald-400';
      case 'declining':
        return 'text-red-400';
      case 'stable':
        return 'text-amber-400';
      default:
        return 'text-zinc-500';
    }
  }

  protected resultBadgeClass(result: string): string {
    switch (result) {
      case 'ac-independent':
        return 'border-emerald-700 bg-emerald-900/30 text-emerald-400';
      case 'ac-with-hints':
        return 'border-amber-700 bg-amber-900/30 text-amber-400';
      case 'ac-after-solution':
        return 'border-red-700 bg-red-900/30 text-red-400';
      default:
        return 'border-zinc-600 bg-zinc-800 text-zinc-400';
    }
  }

  protected resultLabel(result: string): string {
    switch (result) {
      case 'ac-independent':
        return '獨立 AC';
      case 'ac-with-hints':
        return '提示後 AC';
      case 'ac-after-solution':
        return '看解後 AC';
      default:
        return '未完成';
    }
  }

  protected formatWeaknessTag(tag: string): string {
    return tag.replace('weakness:', '');
  }

  // ─── Self-test helpers ───

  protected observationKey(slug: string, tag: string): string {
    return `${slug}::${tag}`;
  }

  protected isRevealed(slug: string, tag: string): boolean {
    return this.revealedObservations().has(this.observationKey(slug, tag));
  }

  protected isRecorded(slug: string, tag: string): boolean {
    return this.recordedAttempts().has(this.observationKey(slug, tag));
  }

  protected revealObservation(slug: string, tag: string): void {
    this.revealedObservations.update((set) => {
      const next = new Set(set);
      next.add(this.observationKey(slug, tag));
      return next;
    });
  }

  protected recordAttempt(
    slug: string,
    quality: RetrievalQuality,
    tag: string,
  ): void {
    const key = this.observationKey(slug, tag);
    this.recordedAttempts.update((set) => {
      const next = new Set(set);
      next.add(key);
      return next;
    });

    this.analyticsService
      .logRetrievalAttempt(slug, quality, tag)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        error: () => this.notificationService.error('無法記錄複習結果'),
      });
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
    this.timelineData.set(null);
    this.expandedWeakness.set(null);
    this.weaknessTrend.set(null);
    this.revealedObservations.set(new Set());
    this.recordedAttempts.set(new Set());
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
      timeline: this.analyticsService.getLearningTimeline(
        project,
        TIMELINE_DAYS,
      ),
      coverage: this.analyticsService.getCoverageMatrix(project),
      weakness: this.analyticsService.getTagSummary(project, 'weakness:'),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ timeline, coverage, weakness }) => {
          this.timelineData.set(timeline);
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
