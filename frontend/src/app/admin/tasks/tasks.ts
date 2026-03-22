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
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ListTodo,
  Loader2,
  CheckCircle2,
  Sun,
  Plus,
  Filter,
  ArrowUpDown,
  X,
  Edit3,
} from 'lucide-angular';
import { TaskService } from '../../core/services/task.service';
import { ProjectService } from '../../core/services/project/project.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ApiTask,
  ApiProject,
  ApiCreateTaskRequest,
  ApiUpdateTaskRequest,
} from '../../core/models';

type SortField = 'due' | 'priority' | 'updated_at';
type ViewMode = 'all' | 'my_day';

const PRIORITY_ORDER: Record<string, number> = {
  High: 3,
  Medium: 2,
  Low: 1,
  '': 0,
};

@Component({
  selector: 'app-tasks',
  standalone: true,
  imports: [DatePipe, FormsModule, LucideAngularModule],
  templateUrl: './tasks.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TasksComponent implements OnInit {
  private readonly taskService = inject(TaskService);
  private readonly projectService = inject(ProjectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  // ─── Data ───
  protected readonly tasks = signal<ApiTask[]>([]);
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly isLoading = signal(false);

  // ─── UI State ───
  protected readonly showCreateForm = signal(false);
  protected readonly viewMode = signal<ViewMode>('all');
  protected readonly sortField = signal<SortField>('due');
  protected readonly filterProject = signal<string>('');
  protected readonly filterPriority = signal<string>('');
  protected readonly filterOverdueOnly = signal(false);
  protected readonly editingTaskId = signal<string | null>(null);

  // ─── Create Form ───
  protected readonly newTitle = signal('');
  protected readonly newDue = signal('');
  protected readonly newPriority = signal('Medium');
  protected readonly newEnergy = signal('Low');
  protected readonly newProjectSlug = signal('');
  protected readonly newMyDay = signal(false);
  protected readonly newNotes = signal('');
  protected readonly isCreating = signal(false);

  // ─── Edit Form ───
  protected readonly editDue = signal('');
  protected readonly editPriority = signal('');
  protected readonly editEnergy = signal('');
  protected readonly editProjectSlug = signal('');
  protected readonly editMyDay = signal(false);
  protected readonly editNotes = signal('');
  protected readonly isSaving = signal(false);

  // ─── Derived State ───
  protected readonly filteredAndSortedTasks = computed(() => {
    let result = this.tasks().filter((t) => t.status !== 'done');

    // View mode filter
    if (this.viewMode() === 'my_day') {
      result = result.filter((t) => t.my_day);
    }

    // Project filter
    const projectFilter = this.filterProject();
    if (projectFilter) {
      result = result.filter((t) => t.project_id === projectFilter);
    }

    // Priority filter
    const priorityFilter = this.filterPriority();
    if (priorityFilter) {
      result = result.filter((t) => t.priority === priorityFilter);
    }

    // Overdue only filter
    if (this.filterOverdueOnly()) {
      result = result.filter((t) => this.isOverdue(t));
    }

    // Sort
    const sort = this.sortField();
    result = [...result].sort((a, b) => {
      // Overdue tasks always on top
      const aOverdue = this.isOverdue(a);
      const bOverdue = this.isOverdue(b);
      if (aOverdue && !bOverdue) return -1;
      if (!aOverdue && bOverdue) return 1;

      if (sort === 'due') {
        if (!a.due && !b.due) return 0;
        if (!a.due) return 1;
        if (!b.due) return -1;
        return new Date(a.due).getTime() - new Date(b.due).getTime();
      }
      if (sort === 'priority') {
        return (PRIORITY_ORDER[b.priority] ?? 0) - (PRIORITY_ORDER[a.priority] ?? 0);
      }
      // updated_at
      return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
    });

    return result;
  });

  protected readonly taskCount = computed(() => this.filteredAndSortedTasks().length);

  protected readonly isEmptyState = computed(() =>
    this.tasks().filter((t) => t.status !== 'done').length === 0,
  );

  protected readonly isMyDayEmpty = computed(() =>
    this.viewMode() === 'my_day' && this.filteredAndSortedTasks().length === 0 && !this.isEmptyState(),
  );

  // ─── Icons ───
  protected readonly ListTodoIcon = ListTodo;
  protected readonly Loader2Icon = Loader2;
  protected readonly CheckCircle2Icon = CheckCircle2;
  protected readonly SunIcon = Sun;
  protected readonly PlusIcon = Plus;
  protected readonly FilterIcon = Filter;
  protected readonly ArrowUpDownIcon = ArrowUpDown;
  protected readonly XIcon = X;
  protected readonly Edit3Icon = Edit3;

  ngOnInit(): void {
    this.loadTasks();
    this.loadProjects();
  }

  // ─── Data Loading ───

  protected loadTasks(): void {
    this.isLoading.set(true);
    this.taskService
      .list()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.tasks.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入任務');
          this.isLoading.set(false);
        },
      });
  }

  private loadProjects(): void {
    this.projectService
      .getAdminProjects()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => this.projects.set(data),
        error: () => {
          /* non-critical */
        },
      });
  }

  // ─── Create ───

  protected toggleCreateForm(): void {
    this.showCreateForm.update((v) => !v);
    if (!this.showCreateForm()) {
      this.resetCreateForm();
    }
  }

  protected createTask(): void {
    const title = this.newTitle().trim();
    if (!title) return;

    this.isCreating.set(true);
    const req: ApiCreateTaskRequest = { title };
    if (this.newDue()) req.due = this.newDue();
    if (this.newPriority()) req.priority = this.newPriority();
    if (this.newEnergy()) req.energy = this.newEnergy();
    if (this.newProjectSlug()) req.project_slug = this.newProjectSlug();
    if (this.newMyDay()) req.my_day = true;
    if (this.newNotes().trim()) req.notes = this.newNotes().trim();

    this.taskService
      .create(req)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('任務已建立');
          this.resetCreateForm();
          this.showCreateForm.set(false);
          this.loadTasks();
          this.isCreating.set(false);
        },
        error: () => {
          this.notificationService.error('建立任務失敗');
          this.isCreating.set(false);
        },
      });
  }

  private resetCreateForm(): void {
    this.newTitle.set('');
    this.newDue.set('');
    this.newPriority.set('Medium');
    this.newEnergy.set('Low');
    this.newProjectSlug.set('');
    this.newMyDay.set(false);
    this.newNotes.set('');
  }

  // ─── Complete ───

  protected completeTask(task: ApiTask): void {
    // Optimistic remove
    const previousTasks = this.tasks();
    this.tasks.update((list) => list.filter((t) => t.id !== task.id));

    this.taskService
      .complete(task.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success(`已完成：${task.title}`);
        },
        error: () => {
          // Rollback
          this.tasks.set(previousTasks);
          this.notificationService.error('完成任務失敗');
        },
      });
  }

  // ─── My Day Toggle ───

  protected toggleMyDay(task: ApiTask): void {
    const newMyDay = !task.my_day;

    // Optimistic update
    const previousTasks = this.tasks();
    this.tasks.update((list) =>
      list.map((t) => (t.id === task.id ? { ...t, my_day: newMyDay } : t)),
    );

    const req: ApiUpdateTaskRequest = { my_day: newMyDay };
    this.taskService
      .update(task.id, req)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        error: () => {
          // Rollback
          this.tasks.set(previousTasks);
          this.notificationService.error('更新 My Day 失敗');
        },
      });
  }

  // ─── Inline Edit ───

  protected openEdit(task: ApiTask): void {
    if (this.editingTaskId() === task.id) {
      this.editingTaskId.set(null);
      return;
    }
    this.editingTaskId.set(task.id);
    this.editDue.set(task.due ?? '');
    this.editPriority.set(task.priority);
    this.editEnergy.set(task.energy);
    this.editMyDay.set(task.my_day);
    this.editNotes.set('');

    // Find project slug from project_id
    const project = this.projects().find((p) => p.id === task.project_id);
    this.editProjectSlug.set(project?.slug ?? '');
  }

  protected cancelEdit(): void {
    this.editingTaskId.set(null);
  }

  protected saveEdit(task: ApiTask): void {
    this.isSaving.set(true);
    const req: ApiUpdateTaskRequest = {};

    if (this.editDue() !== (task.due ?? '')) {
      req.due = this.editDue() || undefined;
    }
    if (this.editPriority() !== task.priority) {
      req.priority = this.editPriority();
    }
    if (this.editEnergy() !== task.energy) {
      req.energy = this.editEnergy();
    }
    if (this.editMyDay() !== task.my_day) {
      req.my_day = this.editMyDay();
    }
    if (this.editProjectSlug()) {
      const currentProject = this.projects().find((p) => p.id === task.project_id);
      if (this.editProjectSlug() !== (currentProject?.slug ?? '')) {
        req.project_slug = this.editProjectSlug();
      }
    } else if (task.project_id) {
      // Clearing project
      req.project_slug = '';
    }
    if (this.editNotes().trim()) {
      req.notes = this.editNotes().trim();
    }

    // Optimistic update
    const previousTasks = this.tasks();
    const editProjectSlug = this.editProjectSlug();
    const updatedProject = this.projects().find((p) => p.slug === editProjectSlug);
    this.tasks.update((list) =>
      list.map((t) =>
        t.id === task.id
          ? {
              ...t,
              due: this.editDue() || null,
              priority: this.editPriority(),
              energy: this.editEnergy(),
              my_day: this.editMyDay(),
              project_id: updatedProject?.id ?? null,
              project_title: updatedProject?.title ?? '',
            }
          : t,
      ),
    );
    this.editingTaskId.set(null);

    this.taskService
      .update(task.id, req)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('任務已更新');
          this.isSaving.set(false);
        },
        error: () => {
          this.tasks.set(previousTasks);
          this.notificationService.error('更新任務失敗');
          this.isSaving.set(false);
        },
      });
  }

  // ─── Helpers ───

  protected isOverdue(task: ApiTask): boolean {
    if (!task.due || task.status === 'done') return false;
    const dueDate = new Date(task.due);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return dueDate < today;
  }

  protected getOverdueDays(task: ApiTask): number {
    if (!task.due) return 0;
    const dueDate = new Date(task.due);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    dueDate.setHours(0, 0, 0, 0);
    const diffMs = today.getTime() - dueDate.getTime();
    return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
  }

  protected getProjectName(projectId: string | null): string | null {
    if (!projectId) return null;
    const project = this.projects().find((p) => p.id === projectId);
    return project?.title ?? null;
  }

  protected getPriorityClass(priority: string): string {
    switch (priority) {
      case 'High':
        return 'border-red-700 bg-red-900/30 text-red-400';
      case 'Medium':
        return 'border-amber-700 bg-amber-900/30 text-amber-400';
      case 'Low':
      default:
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
    }
  }

  protected getEnergyClass(energy: string): string {
    switch (energy) {
      case 'High':
        return 'border-violet-700 bg-violet-900/30 text-violet-400';
      case 'Low':
      default:
        return 'border-zinc-700 bg-zinc-800 text-zinc-400';
    }
  }

  protected setViewMode(mode: ViewMode): void {
    this.viewMode.set(mode);
  }

  protected setSortField(field: SortField): void {
    this.sortField.set(field);
  }

  protected setFilterProject(projectId: string): void {
    this.filterProject.set(projectId);
  }

  protected setFilterPriority(priority: string): void {
    this.filterPriority.set(priority);
  }

  protected toggleOverdueFilter(): void {
    this.filterOverdueOnly.update((v) => !v);
  }
}
