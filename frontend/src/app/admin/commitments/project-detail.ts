import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  ArrowLeft,
  FolderOpen,
  Target,
  ExternalLink,
} from 'lucide-angular';
import { PlanService } from '../../core/services/plan.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ProjectDetail, TaskSummary } from '../../core/models/admin.model';

interface TaskGroup {
  label: string;
  tasks: TaskSummary[];
  color: string;
}

@Component({
  selector: 'app-project-detail',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './project-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly planService = inject(PlanService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly project = signal<ProjectDetail | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly taskGroups = computed<TaskGroup[]>(() => {
    const p = this.project();
    if (!p) return [];
    const groups: TaskGroup[] = [];
    if (p.tasks_by_status.in_progress.length > 0) {
      groups.push({
        label: 'In Progress',
        tasks: p.tasks_by_status.in_progress,
        color: 'text-sky-400',
      });
    }
    if (p.tasks_by_status.todo.length > 0) {
      groups.push({
        label: 'Todo',
        tasks: p.tasks_by_status.todo,
        color: 'text-zinc-300',
      });
    }
    if (p.tasks_by_status.done.length > 0) {
      groups.push({
        label: 'Done',
        tasks: p.tasks_by_status.done,
        color: 'text-emerald-400',
      });
    }
    if (p.tasks_by_status.someday.length > 0) {
      groups.push({
        label: 'Someday',
        tasks: p.tasks_by_status.someday,
        color: 'text-zinc-500',
      });
    }
    return groups;
  });

  protected readonly totalTasks = computed(() => {
    const p = this.project();
    if (!p) return 0;
    const s = p.tasks_by_status;
    return (
      s.in_progress.length + s.todo.length + s.done.length + s.someday.length
    );
  });

  protected readonly doneTasks = computed(
    () => this.project()?.tasks_by_status.done.length ?? 0,
  );

  // Icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly TargetIcon = Target;
  protected readonly ExternalLinkIcon = ExternalLink;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    planned: 'text-zinc-400 bg-zinc-800/50 border-zinc-700/50',
    'in-progress': 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    'on-hold': 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    completed: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    maintained: 'text-blue-400 bg-blue-950/30 border-blue-800/30',
    archived: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.loadProject(id);
    }
  }

  private loadProject(id: string): void {
    this.isLoading.set(true);
    this.planService
      .getProjectDetail(id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.project.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load project');
        },
      });
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }
}
