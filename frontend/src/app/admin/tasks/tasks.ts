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
import {
  LucideAngularModule,
  ListTodo,
  Play,
  Check,
  Clock,
  Zap,
  Search,
  CalendarPlus,
} from 'lucide-angular';
import { FormsModule } from '@angular/forms';
import { PlanService } from '../../core/services/plan.service';
import { TodayService } from '../../core/services/today.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  TaskBacklogItem,
  TaskAdvanceAction,
} from '../../core/models/admin.model';

type StatusFilter = 'all' | 'todo' | 'in-progress' | 'someday';

@Component({
  selector: 'app-tasks',
  standalone: true,
  imports: [LucideAngularModule, FormsModule],
  templateUrl: './tasks.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TasksComponent implements OnInit {
  private readonly planService = inject(PlanService);
  private readonly todayService = inject(TodayService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusTabs: { key: StatusFilter; label: string }[] = [
    { key: 'todo', label: 'Todo' },
    { key: 'in-progress', label: 'Active' },
    { key: 'someday', label: 'Someday' },
    { key: 'all', label: 'All' },
  ];

  protected readonly ENERGY_COLORS: Record<string, string | undefined> = {
    high: 'text-red-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
  };

  protected readonly PRIORITY_COLORS: Record<string, string | undefined> = {
    urgent: 'text-red-400',
    high: 'text-amber-400',
    medium: 'text-zinc-300',
    low: 'text-zinc-500',
  };

  protected readonly tasks = signal<TaskBacklogItem[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly statusFilter = signal<StatusFilter>('todo');
  protected readonly searchQuery = signal('');

  protected readonly filteredTasks = computed(() => {
    const filter = this.statusFilter();
    const query = this.searchQuery().toLowerCase();
    return this.tasks().filter((t) => {
      const matchStatus = filter === 'all' || t.status === filter;
      const matchSearch = !query || t.title.toLowerCase().includes(query);
      return matchStatus && matchSearch;
    });
  });

  protected readonly statusCounts = computed<Record<StatusFilter, number>>(
    () => {
      const all = this.tasks();
      return {
        all: all.length,
        todo: all.filter((t) => t.status === 'todo').length,
        'in-progress': all.filter((t) => t.status === 'in-progress').length,
        someday: all.filter((t) => t.status === 'someday').length,
      };
    },
  );

  protected readonly ListTodoIcon = ListTodo;
  protected readonly PlayIcon = Play;
  protected readonly CheckIcon = Check;
  protected readonly ClockIcon = Clock;
  protected readonly ZapIcon = Zap;
  protected readonly SearchIcon = Search;
  protected readonly CalendarPlusIcon = CalendarPlus;

  ngOnInit(): void {
    this.loadTasks();
  }

  private loadTasks(): void {
    this.isLoading.set(true);
    this.planService
      .getTaskBacklog()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.tasks.set(res.tasks);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load tasks');
        },
      });
  }

  protected setStatusFilter(filter: StatusFilter): void {
    this.statusFilter.set(filter);
  }

  protected advanceTask(id: string, action: TaskAdvanceAction): void {
    this.planService
      .advanceTask(id, action)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.tasks.update((list) =>
            list.map((t) => {
              if (t.id !== id) return t;
              const statusMap: Record<TaskAdvanceAction, string> = {
                start: 'in-progress',
                complete: 'done',
                defer: 'someday',
                drop: 'done',
              };
              return { ...t, status: statusMap[action] };
            }),
          );
        },
        error: () => this.notificationService.error('Operation failed'),
      });
  }

  protected addToToday(taskId: string): void {
    this.todayService
      .planToday([{ task_id: taskId, position: 0 }])
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.tasks.update((list) =>
            list.map((t) =>
              t.id === taskId ? { ...t, is_in_today_plan: true } : t,
            ),
          );
          this.notificationService.success('Added to today plan');
        },
        error: () =>
          this.notificationService.error('Failed to add to today plan'),
      });
  }

  protected onSearchInput(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.searchQuery.set(value);
  }
}
