import {
  Component,
  inject,
  ChangeDetectionStrategy,
  computed,
  signal,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  FileText,
  Send,
  FileEdit,
  TrendingUp,
  FolderOpen,
  Clock,
  Eye,
  Trash2,
  Rss,
  Zap,
  BookOpen,
  Activity,
  Database,
  Tags,
  Loader2,
  Lightbulb,
  BarChart3,
  Workflow,
  ArrowUpRight,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { AuthService } from '../../core/services/auth.service';
import { ProjectService } from '../../core/services/project/project.service';
import { StatsService } from '../../core/services/stats.service';
import { NotificationService } from '../../core/services/notification.service';
import { TaskService } from '../../core/services/task.service';
import { InsightService } from '../../core/services/insight.service';
import { SessionNoteService } from '../../core/services/session-note.service';
import { PipelineService } from '../../core/services/pipeline.service';
import { PipelineActionsComponent } from '../shared/pipeline-actions.component';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import type {
  ApiContent,
  ApiProject,
  ApiStatsOverview,
  ApiDriftReport,
  ApiLearningDashboard,
  ApiDailySummary,
  ProjectStatus,
} from '../../core/models';

interface DeleteTarget {
  id: string;
  title: string;
}

interface StatCard {
  label: string;
  value: number;
  sub: string;
  icon: typeof FileText;
  iconBg: string;
  iconColor: string;
}

const STATUS_LABELS: Record<string, string> = {
  published: 'Published',
  draft: 'Draft',
  review: 'Under Review',
  archived: 'Archived',
};

const STATUS_CLASSES: Record<string, string> = {
  published: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  draft: 'border-amber-800 bg-amber-900/30 text-amber-400',
  review: 'border-sky-800 bg-sky-900/30 text-sky-400',
  archived: 'border-zinc-700 bg-zinc-800 text-zinc-400',
};

const PROJECT_STATUS_LABELS: Record<ProjectStatus, string> = {
  planned: 'Planned',
  'in-progress': 'In Progress',
  'on-hold': 'On Hold',
  completed: 'Completed',
  maintained: 'Maintained',
  archived: 'Archived',
};

const PROJECT_STATUS_CLASSES: Record<ProjectStatus, string> = {
  planned: 'border-zinc-600 bg-zinc-800 text-zinc-300',
  'in-progress': 'border-amber-800 bg-amber-900/30 text-amber-400',
  'on-hold': 'border-orange-800 bg-orange-900/30 text-orange-400',
  completed: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  maintained: 'border-sky-800 bg-sky-900/30 text-sky-400',
  archived: 'border-zinc-700 bg-zinc-800 text-zinc-400',
};

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    DatePipe,
    DecimalPipe,
    RouterLink,
    LucideAngularModule,
    PipelineActionsComponent,
    DeleteConfirmDialogComponent,
  ],
  templateUrl: './dashboard.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardComponent implements OnInit {
  private readonly articleService = inject(ArticleService);
  private readonly authService = inject(AuthService);
  private readonly projectService = inject(ProjectService);
  private readonly statsService = inject(StatsService);
  private readonly notificationService = inject(NotificationService);
  private readonly taskService = inject(TaskService);
  private readonly insightService = inject(InsightService);
  private readonly sessionNoteService = inject(SessionNoteService);
  private readonly pipelineService = inject(PipelineService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly articles = signal<ApiContent[]>([]);
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly stats = signal<ApiStatsOverview | null>(null);
  protected readonly drift = signal<ApiDriftReport | null>(null);
  protected readonly learning = signal<ApiLearningDashboard | null>(null);
  protected readonly isLoadingStats = signal(false);
  protected readonly currentUser = this.authService.currentUser;

  protected readonly todaySummary = signal<ApiDailySummary | null>(null);
  protected readonly insightCount = signal(0);
  protected readonly latestHypothesis = signal('');
  protected readonly weekCapacity = signal<number | null>(null);
  protected readonly capacityTrend = signal<'up' | 'stable' | 'down'>('stable');
  protected readonly isSyncingNotion = signal(false);
  protected readonly isSyncingObsidian = signal(false);
  protected readonly isSyncingCollect = signal(false);

  protected readonly deleteTarget = signal<DeleteTarget | null>(null);
  protected readonly isDeleting = signal(false);
  protected readonly deleteType = signal<'article' | 'project'>('article');

  protected readonly statCards = computed<StatCard[]>(() => {
    const s = this.stats();
    if (!s) {
      return [];
    }
    const notesSub = this.formatByType(s.notes.by_type);
    const contentSub = this.formatByStatus(s.contents.by_status, s.contents.published, 'published');
    const collectedSub = this.formatByStatus(s.collected.by_status, s.collected.by_status?.['unread'] ?? 0, 'unread');
    return [
      { label: 'Contents', value: s.contents.total, sub: contentSub, icon: FileText, iconBg: 'bg-zinc-800', iconColor: 'text-zinc-300' },
      { label: 'Collected', value: s.collected.total, sub: collectedSub, icon: Rss, iconBg: 'bg-amber-900/30', iconColor: 'text-amber-400' },
      { label: 'Feeds', value: s.feeds.total, sub: `${s.feeds.enabled} enabled`, icon: Rss, iconBg: 'bg-sky-900/30', iconColor: 'text-sky-400' },
      { label: 'Flow Runs', value: s.flow_runs.total, sub: `${s.flow_runs.by_status?.['failed'] ?? 0} failed`, icon: Zap, iconBg: 'bg-violet-900/30', iconColor: 'text-violet-400' },
      { label: 'Projects', value: s.projects.total, sub: `${s.projects.by_status?.['in-progress'] ?? 0} active`, icon: FolderOpen, iconBg: 'bg-emerald-900/30', iconColor: 'text-emerald-400' },
      { label: 'Review', value: s.reviews.total, sub: `${s.reviews.pending} pending`, icon: FileEdit, iconBg: 'bg-amber-900/30', iconColor: 'text-amber-400' },
      { label: 'Notes', value: s.notes.total, sub: notesSub, icon: BookOpen, iconBg: 'bg-sky-900/30', iconColor: 'text-sky-400' },
      { label: 'Activity', value: s.activity.total, sub: `${s.activity.last_24h} last 24h · ${s.activity.last_7d} last 7d`, icon: Activity, iconBg: 'bg-emerald-900/30', iconColor: 'text-emerald-400' },
      { label: 'Sources', value: s.sources.total, sub: `${s.sources.enabled} enabled`, icon: Database, iconBg: 'bg-zinc-800', iconColor: 'text-zinc-300' },
      { label: 'Tags', value: s.tags.canonical, sub: `${s.tags.unconfirmed} unconfirmed`, icon: Tags, iconBg: 'bg-amber-900/30', iconColor: 'text-amber-400' },
    ];
  });

  protected readonly recentArticles = computed(() =>
    [...this.articles()]
      .sort(
        (a, b) =>
          new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime(),
      )
      .slice(0, 5),
  );

  protected readonly FileTextIcon = FileText;
  protected readonly SendIcon = Send;
  protected readonly FileEditIcon = FileEdit;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly ClockIcon = Clock;
  protected readonly EyeIcon = Eye;
  protected readonly Trash2Icon = Trash2;
  protected readonly Loader2Icon = Loader2;
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly BarChart3Icon = BarChart3;
  protected readonly WorkflowIcon = Workflow;
  protected readonly ArrowUpRightIcon = ArrowUpRight;

  ngOnInit(): void {
    this.loadStats();
    this.loadDrift();
    this.loadLearning();
    this.loadArticles();
    this.loadProjects();
    this.loadTodaySummary();
    this.loadInsights();
    this.loadWeekCapacity();
  }

  private loadStats(): void {
    this.isLoadingStats.set(true);
    this.statsService
      .getOverview()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.stats.set(data);
          this.isLoadingStats.set(false);
        },
        error: () => {
          this.isLoadingStats.set(false);
          this.notificationService.error('無法載入統計資料');
        },
      });
  }

  private loadDrift(): void {
    this.statsService
      .getDrift()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => this.drift.set(data),
        error: () => {
          /* drift 非關鍵，靜默失敗 */
        },
      });
  }

  private loadLearning(): void {
    this.statsService
      .getLearning()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => this.learning.set(data),
        error: () => {
          /* learning 非關鍵，靜默失敗 */
        },
      });
  }

  private loadArticles(): void {
    this.articleService
      .getArticles()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => this.articles.set(response.articles),
        error: () => this.notificationService.error('無法載入文章'),
      });
  }

  private loadProjects(): void {
    this.projectService
      .getAdminProjects()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (projectList) => this.projects.set(projectList),
        error: () => this.notificationService.error('無法載入專案'),
      });
  }

  protected requestDeleteArticle(id: string, title: string): void {
    this.deleteType.set('article');
    this.deleteTarget.set({ id, title });
  }

  protected requestDeleteProject(id: string, title: string): void {
    this.deleteType.set('project');
    this.deleteTarget.set({ id, title });
  }

  protected cancelDelete(): void {
    this.deleteTarget.set(null);
  }

  protected confirmDelete(): void {
    const target = this.deleteTarget();
    if (!target) {
      return;
    }

    this.isDeleting.set(true);

    const deleteObs =
      this.deleteType() === 'article'
        ? this.articleService.deleteArticle(target.id)
        : this.projectService.deleteProject(target.id);

    deleteObs.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.deleteTarget.set(null);
        this.isDeleting.set(false);
        if (this.deleteType() === 'article') {
          this.loadArticles();
        } else {
          this.loadProjects();
        }
      },
      error: () => {
        this.isDeleting.set(false);
        this.notificationService.error('刪除失敗');
      },
    });
  }

  protected toggleProjectPublic(project: ApiProject): void {
    const newPublic = !project.is_public;
    this.projectService
      .updateProject(project.id, { is_public: newPublic })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.projects.update((list) =>
            list.map((p) =>
              p.id === project.id ? { ...p, is_public: newPublic } : p,
            ),
          );
          this.notificationService.success(
            newPublic ? '已設為公開' : '已設為非公開',
          );
        },
        error: () => this.notificationService.error('更新失敗'),
      });
  }

  protected getProjectStatusLabel(status: ProjectStatus): string {
    return PROJECT_STATUS_LABELS[status];
  }

  protected getProjectStatusClass(status: ProjectStatus): string {
    return PROJECT_STATUS_CLASSES[status];
  }

  protected getStatusLabel(status: string): string {
    return STATUS_LABELS[status] ?? status;
  }

  protected getStatusClass(status: string): string {
    return STATUS_CLASSES[status] ?? STATUS_CLASSES['archived'];
  }

  private loadTodaySummary(): void {
    this.taskService
      .dailySummary()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => this.todaySummary.set(data),
        error: () => {
          /* 非關鍵，靜默失敗 */
        },
      });
  }

  private loadInsights(): void {
    this.insightService
      .list({ status: 'unverified', limit: 1 })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.insightCount.set(data.unverified_count);
          if (data.insights.length > 0) {
            this.latestHypothesis.set(data.insights[0].hypothesis);
          }
        },
        error: () => {
          /* 非關鍵，靜默失敗 */
        },
      });
  }

  private loadWeekCapacity(): void {
    this.sessionNoteService
      .list(undefined, 'metrics', 7)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (notes) => {
          if (notes.length === 0) return;
          const capacities = notes
            .map((n) => {
              const meta = n.metadata as Record<string, number> | null;
              if (!meta) return null;
              return (meta['tasks_committed'] ?? 0) + (meta['tasks_pulled'] ?? 0);
            })
            .filter((v): v is number => v !== null);
          if (capacities.length === 0) return;
          const avg = capacities.reduce((sum, v) => sum + v, 0) / capacities.length;
          this.weekCapacity.set(Math.round(avg * 10) / 10);

          // 趨勢：最近 3 天 vs 前 4 天
          const recent = capacities.slice(0, Math.min(3, capacities.length));
          const previous = capacities.slice(3);
          if (recent.length > 0 && previous.length > 0) {
            const recentAvg = recent.reduce((s, v) => s + v, 0) / recent.length;
            const prevAvg = previous.reduce((s, v) => s + v, 0) / previous.length;
            const diff = recentAvg - prevAvg;
            if (diff > 0.5) {
              this.capacityTrend.set('up');
            } else if (diff < -0.5) {
              this.capacityTrend.set('down');
            } else {
              this.capacityTrend.set('stable');
            }
          }
        },
        error: () => {
          /* 非關鍵，靜默失敗 */
        },
      });
  }

  protected syncNotion(): void {
    this.isSyncingNotion.set(true);
    this.pipelineService
      .triggerNotionSync()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isSyncingNotion.set(false);
          this.notificationService.success('Notion 同步完成');
        },
        error: () => {
          this.isSyncingNotion.set(false);
          this.notificationService.error('Notion 同步失敗');
        },
      });
  }

  protected syncObsidian(): void {
    this.isSyncingObsidian.set(true);
    this.pipelineService
      .triggerSync()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isSyncingObsidian.set(false);
          this.notificationService.success('Obsidian 同步完成');
        },
        error: () => {
          this.isSyncingObsidian.set(false);
          this.notificationService.error('Obsidian 同步失敗');
        },
      });
  }

  protected syncCollect(): void {
    this.isSyncingCollect.set(true);
    this.pipelineService
      .triggerCollect()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isSyncingCollect.set(false);
          this.notificationService.success('RSS 收集完成');
        },
        error: () => {
          this.isSyncingCollect.set(false);
          this.notificationService.error('RSS 收集失敗');
        },
      });
  }

  /** 從 by_type map 取前 3 個 type 摘要，例如 "5 til · 3 note · 2 article" */
  private formatByType(byType: Record<string, number>): string {
    const entries = Object.entries(byType)
      .filter(([, count]) => count > 0)
      .sort(([, a], [, b]) => b - a);
    if (entries.length === 0) {
      return 'Obsidian 同步後顯示';
    }
    return entries
      .slice(0, 3)
      .map(([type, count]) => `${count} ${type}`)
      .join(' · ');
  }

  /** 格式化 by_status 摘要 */
  private formatByStatus(byStatus: Record<string, number>, highlight: number, label: string): string {
    if (!byStatus || Object.keys(byStatus).length === 0) {
      return `${highlight} ${label}`;
    }
    return `${highlight} ${label}`;
  }
}
