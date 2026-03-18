import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  FolderOpen,
  Plus,
  Pencil,
  Trash2,
  Loader2,
  RefreshCw,
  Eye,
  Github,
  ExternalLink,
} from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { NotificationService } from '../../core/services/notification.service';
import { DeleteConfirmDialogComponent } from '../shared/delete-confirm-dialog.component';
import type { ApiProject, ProjectStatus } from '../../core/models';

type StatusFilter = ProjectStatus | 'all';

const STATUS_CONFIG: Record<ProjectStatus, { label: string; classes: string }> = {
  planned: { label: 'Planned', classes: 'border-zinc-600 bg-zinc-800 text-zinc-300' },
  'in-progress': { label: 'In Progress', classes: 'border-amber-800 bg-amber-900/30 text-amber-400' },
  'on-hold': { label: 'On Hold', classes: 'border-orange-800 bg-orange-900/30 text-orange-400' },
  completed: { label: 'Completed', classes: 'border-emerald-800 bg-emerald-900/30 text-emerald-400' },
  maintained: { label: 'Maintained', classes: 'border-sky-800 bg-sky-900/30 text-sky-400' },
  archived: { label: 'Archived', classes: 'border-zinc-700 bg-zinc-800 text-zinc-500' },
};

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'in-progress', label: 'In Progress' },
  { value: 'completed', label: 'Completed' },
  { value: 'maintained', label: 'Maintained' },
  { value: 'planned', label: 'Planned' },
  { value: 'on-hold', label: 'On Hold' },
  { value: 'archived', label: 'Archived' },
];

@Component({
  selector: 'app-admin-projects',
  standalone: true,
  imports: [
    DatePipe,
    RouterLink,
    LucideAngularModule,
    DeleteConfirmDialogComponent,
  ],
  templateUrl: './projects.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AdminProjectsComponent implements OnInit {
  private readonly projectService = inject(ProjectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly statusFilter = signal<StatusFilter>('all');

  protected readonly filteredProjects = computed(() => {
    const all = this.projects();
    const f = this.statusFilter();
    return f === 'all' ? all : all.filter((p) => p.status === f);
  });

  protected readonly statusCounts = computed(() => {
    const all = this.projects();
    const counts: Partial<Record<ProjectStatus, number>> = {};
    for (const p of all) {
      counts[p.status] = (counts[p.status] ?? 0) + 1;
    }
    return counts;
  });

  protected readonly deleteTarget = signal<{ id: string; title: string } | null>(null);
  protected readonly isDeleting = signal(false);

  protected readonly statusFilters = STATUS_FILTERS;

  // ─── Icons ───
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly PlusIcon = Plus;
  protected readonly PencilIcon = Pencil;
  protected readonly Trash2Icon = Trash2;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly EyeIcon = Eye;
  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;

  ngOnInit(): void {
    this.loadProjects();
  }

  protected loadProjects(): void {
    this.isLoading.set(true);
    this.projectService
      .getAdminProjects()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.projects.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入專案');
          this.isLoading.set(false);
        },
      });
  }

  protected setFilter(f: StatusFilter): void {
    this.statusFilter.set(f);
  }

  protected togglePublic(project: ApiProject): void {
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
          this.notificationService.success(newPublic ? '已設為公開' : '已設為非公開');
        },
        error: () => this.notificationService.error('更新失敗'),
      });
  }

  protected getStatusLabel(status: ProjectStatus): string {
    return STATUS_CONFIG[status]?.label ?? status;
  }

  protected getStatusClass(status: ProjectStatus): string {
    return STATUS_CONFIG[status]?.classes ?? STATUS_CONFIG['archived'].classes;
  }

  protected requestDelete(project: ApiProject): void {
    this.deleteTarget.set({ id: project.id, title: project.title });
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
    this.projectService
      .deleteProject(target.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.projects.update((list) => list.filter((p) => p.id !== target.id));
          this.deleteTarget.set(null);
          this.isDeleting.set(false);
          this.notificationService.success('已刪除');
        },
        error: () => {
          this.isDeleting.set(false);
          this.notificationService.error('刪除失敗');
          this.deleteTarget.set(null);
        },
      });
  }
}
