import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  type OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LucideAngularModule } from 'lucide-angular';
import {
  Star,
  AlertTriangle,
  Calendar,
  Notebook,
  BarChart3,
} from 'lucide-angular/src/icons';
import { forkJoin } from 'rxjs';

import { TaskService } from '../../core/services/task.service';
import { SessionNoteService } from '../../core/services/session-note.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiTask, ApiSessionNote } from '../../core/models';

@Component({
  selector: 'app-today',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './today.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodayComponent implements OnInit {
  private readonly taskService = inject(TaskService);
  private readonly sessionNoteService = inject(SessionNoteService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly StarIcon = Star;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly CalendarIcon = Calendar;
  protected readonly NotebookIcon = Notebook;
  protected readonly BarChartIcon = BarChart3;

  protected readonly isLoading = signal(true);
  protected readonly tasks = signal<ApiTask[]>([]);
  protected readonly sessionNotes = signal<ApiSessionNote[]>([]);
  protected readonly metricsNotes = signal<ApiSessionNote[]>([]);

  private readonly today = new Date().toISOString().slice(0, 10);

  protected readonly todayLabel = computed(() => {
    const weekdays = ['日', '一', '二', '三', '四', '五', '六'];
    const d = new Date();
    return `${this.today}（${weekdays[d.getDay()]}）`;
  });

  protected readonly myDayTasks = computed(() =>
    this.tasks().filter((t) => t.my_day && t.status !== 'done'),
  );

  protected readonly overdueTasks = computed(() =>
    this.tasks()
      .filter((t) => t.status !== 'done' && t.due !== null && t.due < this.today)
      .sort((a, b) => (a.due ?? '').localeCompare(b.due ?? '')),
  );

  protected readonly todayDueTasks = computed(() =>
    this.tasks().filter((t) => t.status !== 'done' && t.due === this.today && !t.my_day),
  );

  protected readonly yesterdayNotes = computed(() =>
    this.sessionNotes().filter(
      (n) => n.note_type === 'plan' || n.note_type === 'reflection',
    ),
  );

  protected readonly planningHistory = computed(() => this.metricsNotes());

  ngOnInit(): void {
    this.loadData();
  }

  protected isOverdue(task: ApiTask): boolean {
    return task.due !== null && task.due < this.today;
  }

  protected overdueDays(task: ApiTask): number {
    if (!task.due) return 0;
    const due = new Date(task.due + 'T00:00:00');
    const now = new Date(this.today + 'T00:00:00');
    const days = Math.floor((now.getTime() - due.getTime()) / 86400000);
    return Number.isNaN(days) ? 0 : days;
  }

  protected priorityClass(priority: string): string {
    switch (priority) {
      case 'High':
        return 'text-red-400';
      case 'Medium':
        return 'text-amber-400';
      default:
        return 'text-zinc-500';
    }
  }

  protected rateClass(note: ApiSessionNote): string {
    const rate = this.completionRate(note);
    if (rate >= 80) return 'text-emerald-400';
    if (rate >= 50) return 'text-amber-400';
    return 'text-red-400';
  }

  protected rateDisplay(note: ApiSessionNote): string {
    return Math.round(this.completionRate(note)) + '%';
  }

  protected planned(note: ApiSessionNote): number {
    return (note.metadata as Record<string, number> | null)?.['tasks_planned'] ?? 0;
  }

  protected completed(note: ApiSessionNote): number {
    return (note.metadata as Record<string, number> | null)?.['tasks_completed'] ?? 0;
  }

  private completionRate(note: ApiSessionNote): number {
    return ((note.metadata as Record<string, number> | null)?.['completion_rate'] ?? 0) * 100;
  }

  private loadData(): void {
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

    forkJoin({
      tasks: this.taskService.list(),
      notes: this.sessionNoteService.list(yesterday, undefined, 2),
      metrics: this.sessionNoteService.list(undefined, 'metrics', 7),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ tasks, notes, metrics }) => {
          this.tasks.set(tasks);
          this.sessionNotes.set(notes);
          this.metricsNotes.set(metrics);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入今日資料');
          this.isLoading.set(false);
        },
      });
  }
}
