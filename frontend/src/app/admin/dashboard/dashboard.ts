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
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  FileText,
  Send,
  FileEdit,
  TrendingUp,
  Plus,
  PenSquare,
  FolderOpen,
  Tag,
  Settings,
  Clock,
  MoreHorizontal,
  Edit,
  Eye,
  Trash2,
  AlertTriangle,
  Activity,
  RefreshCw,
  Loader2,
  RotateCcw,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { AuthService } from '../../core/services/auth.service';
import { ProjectService } from '../../core/services/project/project.service';
import { PipelineService } from '../../core/services/pipeline.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiContent, ApiProject, ProjectStatus } from '../../core/models';

interface DeleteTarget {
  id: string;
  title: string;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [DatePipe, RouterLink, LucideAngularModule],
  templateUrl: './dashboard.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardComponent implements OnInit {
  private readonly articleService = inject(ArticleService);
  private readonly authService = inject(AuthService);
  private readonly projectService = inject(ProjectService);
  private readonly pipelineService = inject(PipelineService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly articles = signal<ApiContent[]>([]);
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly currentUser = this.authService.currentUser;

  protected readonly deleteTarget = signal<DeleteTarget | null>(null);
  protected readonly isDeleting = signal(false);
  protected readonly deleteType = signal<'article' | 'project'>('article');

  protected readonly totalArticles = computed(() => this.articles().length);

  protected readonly publishedArticles = computed(
    () =>
      this.articles().filter((article) => article.status === 'published')
        .length,
  );

  protected readonly draftArticles = computed(
    () =>
      this.articles().filter((article) => article.status === 'draft').length,
  );

  protected readonly publishRate = computed(() => {
    const total = this.totalArticles();
    const published = this.publishedArticles();
    return total > 0 ? Math.round((published / total) * 100) : 0;
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
  protected readonly PlusIcon = Plus;
  protected readonly PenSquareIcon = PenSquare;
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly TagIcon = Tag;
  protected readonly SettingsIcon = Settings;
  protected readonly ClockIcon = Clock;
  protected readonly MoreHorizontalIcon = MoreHorizontal;
  protected readonly EditIcon = Edit;
  protected readonly EyeIcon = Eye;
  protected readonly Trash2Icon = Trash2;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly ActivityIcon = Activity;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly Loader2Icon = Loader2;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly triggering = this.pipelineService.triggering;

  ngOnInit(): void {
    this.articleService
      .getArticles()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => this.articles.set(response.articles),
      });

    this.projectService
      .getAdminProjects()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (projectList) => this.projects.set(projectList),
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
        // Reload data
        if (this.deleteType() === 'article') {
          this.articleService
            .getArticles()
            .pipe(takeUntilDestroyed(this.destroyRef))
            .subscribe({
              next: (response) => this.articles.set(response.articles),
            });
        } else {
          this.projectService
            .getAdminProjects()
            .pipe(takeUntilDestroyed(this.destroyRef))
            .subscribe({
              next: (projectList) => this.projects.set(projectList),
            });
        }
      },
      error: () => {
        this.isDeleting.set(false);
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
    const labels: Record<ProjectStatus, string> = {
      completed: 'Completed',
      'in-progress': 'In Progress',
      maintained: 'Maintained',
      archived: 'Archived',
    };
    return labels[status];
  }

  protected getProjectStatusClass(status: ProjectStatus): string {
    const classes: Record<ProjectStatus, string> = {
      completed: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
      'in-progress': 'border-amber-800 bg-amber-900/30 text-amber-400',
      maintained: 'border-sky-800 bg-sky-900/30 text-sky-400',
      archived: 'border-zinc-700 bg-zinc-800 text-zinc-400',
    };
    return classes[status];
  }

  protected getStatusLabel(status: string): string {
    switch (status) {
      case 'published':
        return 'Published';
      case 'draft':
        return 'Draft';
      case 'review':
        return 'Under Review';
      case 'archived':
        return 'Archived';
      default:
        return status;
    }
  }

  protected triggerSync(): void {
    this.pipelineService
      .triggerSync()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('Obsidian 同步已觸發'),
        error: () => this.notificationService.error('同步觸發失敗'),
      });
  }

  protected triggerCollect(): void {
    this.pipelineService
      .triggerCollect()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('RSS 收集已觸發'),
        error: () => this.notificationService.error('收集觸發失敗'),
      });
  }

  protected triggerNotionSync(): void {
    this.pipelineService
      .triggerNotionSync()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('Notion 同步已觸發'),
        error: () => this.notificationService.error('Notion 同步失敗'),
      });
  }

  protected triggerReconcile(): void {
    this.pipelineService
      .triggerReconcile()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('全量比對已觸發'),
        error: () => this.notificationService.error('比對觸發失敗'),
      });
  }

  protected triggerBookmark(): void {
    this.pipelineService
      .triggerBookmark()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('書籤生成已觸發'),
        error: () => this.notificationService.error('書籤生成失敗'),
      });
  }

  protected getStatusClass(status: string): string {
    switch (status) {
      case 'published':
        return 'border-emerald-800 bg-emerald-900/30 text-emerald-400';
      case 'draft':
        return 'border-amber-800 bg-amber-900/30 text-amber-400';
      case 'review':
        return 'border-sky-800 bg-sky-900/30 text-sky-400';
      case 'archived':
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
      default:
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
    }
  }
}
