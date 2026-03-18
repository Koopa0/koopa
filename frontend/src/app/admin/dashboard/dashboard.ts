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
  Brain,
  Database,
  Tags,
  Loader2,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { AuthService } from '../../core/services/auth.service';
import { ProjectService } from '../../core/services/project/project.service';
import { StatsService } from '../../core/services/stats.service';
import { NotificationService } from '../../core/services/notification.service';
import { PipelineActionsComponent } from '../shared/pipeline-actions.component';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import type {
  ApiContent,
  ApiProject,
  ApiStatsOverview,
  ApiDriftReport,
  ApiLearningDashboard,
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
  completed: 'Completed',
  'in-progress': 'In Progress',
  maintained: 'Maintained',
  archived: 'Archived',
};

const PROJECT_STATUS_CLASSES: Record<ProjectStatus, string> = {
  completed: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  'in-progress': 'border-amber-800 bg-amber-900/30 text-amber-400',
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
  private readonly destroyRef = inject(DestroyRef);

  protected readonly articles = signal<ApiContent[]>([]);
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly stats = signal<ApiStatsOverview | null>(null);
  protected readonly drift = signal<ApiDriftReport | null>(null);
  protected readonly learning = signal<ApiLearningDashboard | null>(null);
  protected readonly isLoadingStats = signal(false);
  protected readonly currentUser = this.authService.currentUser;

  protected readonly deleteTarget = signal<DeleteTarget | null>(null);
  protected readonly isDeleting = signal(false);
  protected readonly deleteType = signal<'article' | 'project'>('article');

  protected readonly statCards = computed<StatCard[]>(() => {
    const s = this.stats();
    if (!s) {
      return [];
    }
    return [
      { label: 'Contents', value: s.contents.total, sub: `${s.contents.published} published`, icon: FileText, iconBg: 'bg-zinc-800', iconColor: 'text-zinc-300' },
      { label: 'Collected', value: s.collected.total, sub: `${s.collected.by_status?.['unread'] ?? 0} unread`, icon: Rss, iconBg: 'bg-amber-900/30', iconColor: 'text-amber-400' },
      { label: 'Feeds', value: s.feeds.total, sub: `${s.feeds.enabled} enabled`, icon: Rss, iconBg: 'bg-sky-900/30', iconColor: 'text-sky-400' },
      { label: 'Flow Runs', value: s.flow_runs.total, sub: `${s.flow_runs.by_status?.['failed'] ?? 0} failed`, icon: Zap, iconBg: 'bg-violet-900/30', iconColor: 'text-violet-400' },
      { label: 'Projects', value: s.projects.total, sub: `${s.projects.by_status?.['in-progress'] ?? 0} active`, icon: FolderOpen, iconBg: 'bg-emerald-900/30', iconColor: 'text-emerald-400' },
      { label: 'Review', value: s.reviews.total, sub: `${s.reviews.pending} pending`, icon: FileEdit, iconBg: 'bg-amber-900/30', iconColor: 'text-amber-400' },
      { label: 'Notes', value: s.notes.total, sub: `${Object.keys(s.notes.by_type).length} types`, icon: BookOpen, iconBg: 'bg-sky-900/30', iconColor: 'text-sky-400' },
      { label: 'Activity', value: s.activity.total, sub: `${s.activity.last_24h} today`, icon: Activity, iconBg: 'bg-emerald-900/30', iconColor: 'text-emerald-400' },
      { label: 'Spaced', value: s.spaced.enrolled, sub: `${s.spaced.due} due`, icon: Brain, iconBg: 'bg-violet-900/30', iconColor: 'text-violet-400' },
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

  ngOnInit(): void {
    this.loadStats();
    this.loadDrift();
    this.loadLearning();
    this.loadArticles();
    this.loadProjects();
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
    const newPublic = !project.public;
    this.projectService
      .updateProject(project.id, { public: newPublic })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.projects.update((list) =>
            list.map((p) =>
              p.id === project.id ? { ...p, public: newPublic } : p,
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
}
