import {
  Component,
  inject,
  ChangeDetectionStrategy,
  computed,
  signal,
} from '@angular/core';
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
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { AuthService } from '../../core/services/auth.service';
import { ProjectService } from '../../core/services/project/project.service';
import { ProjectStatus } from '../../core/models';

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
export class DashboardComponent {
  private readonly articleService = inject(ArticleService);
  private readonly authService = inject(AuthService);
  private readonly projectService = inject(ProjectService);

  protected readonly articles = this.articleService.articleList;
  protected readonly projects = this.projectService.allProjects;
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
          new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
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

    deleteObs.subscribe({
      next: () => {
        this.deleteTarget.set(null);
        this.isDeleting.set(false);
      },
      error: () => {
        this.isDeleting.set(false);
      },
    });
  }

  protected getProjectStatusLabel(status: ProjectStatus): string {
    const labels: Record<ProjectStatus, string> = {
      completed: 'Completed',
      'in-progress': 'In Progress',
      maintained: 'Maintained',
    };
    return labels[status];
  }

  protected getProjectStatusClass(status: ProjectStatus): string {
    const classes: Record<ProjectStatus, string> = {
      completed: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
      'in-progress': 'border-amber-800 bg-amber-900/30 text-amber-400',
      maintained: 'border-sky-800 bg-sky-900/30 text-sky-400',
    };
    return classes[status];
  }

  protected getStatusLabel(status: string): string {
    switch (status) {
      case 'published':
        return '已發布';
      case 'draft':
        return '草稿';
      case 'archived':
        return '封存';
      default:
        return status;
    }
  }

  protected getStatusClass(status: string): string {
    switch (status) {
      case 'published':
        return 'border-emerald-800 bg-emerald-900/30 text-emerald-400';
      case 'draft':
        return 'border-amber-800 bg-amber-900/30 text-amber-400';
      case 'archived':
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
      default:
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
    }
  }
}
