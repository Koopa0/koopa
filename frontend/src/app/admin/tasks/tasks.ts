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
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ListTodo,
  Loader2,
  RefreshCw,
  Circle,
  Clock,
  CheckCircle2,
} from 'lucide-angular';
import { TaskService } from '../../core/services/task.service';
import { ProjectService } from '../../core/services/project/project.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiTask, ApiProject, TaskStatus } from '../../core/models';

interface KanbanColumn {
  status: TaskStatus;
  label: string;
  icon: typeof Circle;
  headerClass: string;
}

const COLUMNS: KanbanColumn[] = [
  { status: 'todo', label: 'Todo', icon: Circle, headerClass: 'text-zinc-400' },
  { status: 'in-progress', label: 'In Progress', icon: Clock, headerClass: 'text-amber-400' },
  { status: 'done', label: 'Done', icon: CheckCircle2, headerClass: 'text-emerald-400' },
];

@Component({
  selector: 'app-tasks',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './tasks.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TasksComponent implements OnInit {
  private readonly taskService = inject(TaskService);
  private readonly projectService = inject(ProjectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly tasks = signal<ApiTask[]>([]);
  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly isLoading = signal(false);

  /** 是否顯示已完成任務 */
  protected readonly showDone = signal(false);

  protected readonly columns = COLUMNS;

  protected readonly tasksByStatus = computed(() => {
    const all = this.tasks();
    const result: Record<TaskStatus, ApiTask[]> = {
      todo: [],
      'in-progress': [],
      done: [],
    };
    for (const task of all) {
      result[task.status].push(task);
    }
    return result;
  });

  protected readonly visibleColumns = computed(() => {
    if (this.showDone()) {
      return COLUMNS;
    }
    return COLUMNS.filter((c) => c.status !== 'done');
  });

  // ─── Icons ───
  protected readonly ListTodoIcon = ListTodo;
  protected readonly Loader2Icon = Loader2;
  protected readonly RefreshCwIcon = RefreshCw;

  ngOnInit(): void {
    this.loadTasks();
    this.loadProjects();
  }

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

  protected toggleShowDone(): void {
    this.showDone.update((v) => !v);
  }

  protected getProjectName(projectId: string | null): string | null {
    if (!projectId) {
      return null;
    }
    const project = this.projects().find((p) => p.id === projectId);
    return project ? project.title : null;
  }

  protected isOverdue(task: ApiTask): boolean {
    if (!task.due || task.status === 'done') {
      return false;
    }
    return new Date(task.due) < new Date();
  }

  protected getColumnCount(status: TaskStatus): number {
    return this.tasksByStatus()[status].length;
  }
}
