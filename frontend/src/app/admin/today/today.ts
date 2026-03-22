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
import { FormsModule } from '@angular/forms';
import { LucideAngularModule } from 'lucide-angular';
import {
  Star,
  AlertTriangle,
  Calendar,
  Notebook,
  BarChart3,
  CheckCircle2,
  Sun,
  Plus,
  Lightbulb,
  X,
} from 'lucide-angular/src/icons';
import { forkJoin } from 'rxjs';

import { TaskService } from '../../core/services/task.service';
import { InsightService } from '../../core/services/insight.service';
import { SessionNoteService } from '../../core/services/session-note.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiTask, ApiSessionNote, ApiInsight, ApiDailySummary } from '../../core/models';

@Component({
  selector: 'app-today',
  standalone: true,
  imports: [LucideAngularModule, FormsModule],
  templateUrl: './today.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodayComponent implements OnInit {
  private readonly taskService = inject(TaskService);
  private readonly insightService = inject(InsightService);
  private readonly sessionNoteService = inject(SessionNoteService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly StarIcon = Star;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly CalendarIcon = Calendar;
  protected readonly NotebookIcon = Notebook;
  protected readonly BarChartIcon = BarChart3;
  protected readonly CheckIcon = CheckCircle2;
  protected readonly SunIcon = Sun;
  protected readonly PlusIcon = Plus;
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly CloseIcon = X;

  protected readonly isLoading = signal(true);
  protected readonly tasks = signal<ApiTask[]>([]);
  protected readonly sessionNotes = signal<ApiSessionNote[]>([]);
  protected readonly metricsNotes = signal<ApiSessionNote[]>([]);
  protected readonly insights = signal<ApiInsight[]>([]);
  protected readonly unverifiedCount = signal(0);
  protected readonly dailySummary = signal<ApiDailySummary | null>(null);

  // Task creation form
  protected readonly isCreating = signal(false);
  protected readonly newTaskTitle = signal('');

  // Evidence input
  protected readonly evidenceTarget = signal<number | null>(null);
  protected readonly evidenceText = signal('');

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

  protected readonly summaryDisplay = computed(() => {
    const s = this.dailySummary();
    if (!s) return null;
    const myDayRate = s.my_day_tasks_total > 0
      ? Math.round((s.my_day_tasks_completed / s.my_day_tasks_total) * 100)
      : 0;
    return {
      myDayCompleted: s.my_day_tasks_completed,
      myDayTotal: s.my_day_tasks_total,
      myDayRate,
      extraCompleted: s.non_my_day_completed,
      totalCompleted: s.total_completed,
    };
  });

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

  // --- Task Actions ---

  protected completeTask(task: ApiTask): void {
    this.tasks.update((tasks) => tasks.filter((t) => t.id !== task.id));

    this.taskService
      .complete(task.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          const nextRecurrence = result['next_recurrence'] as string | undefined;
          if (nextRecurrence) {
            this.notificationService.success(`完成「${task.title}」，下次 due: ${nextRecurrence}`);
          } else {
            this.notificationService.success(`完成「${task.title}」`);
          }
          this.refreshSummary();
        },
        error: () => {
          this.tasks.update((tasks) => [...tasks, task]);
          this.notificationService.error('完成任務失敗');
        },
      });
  }

  protected addToMyDay(task: ApiTask): void {
    this.tasks.update((tasks) =>
      tasks.map((t) => (t.id === task.id ? { ...t, my_day: true } : t)),
    );

    this.taskService
      .update(task.id, { my_day: true })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        error: () => {
          this.tasks.update((tasks) =>
            tasks.map((t) => (t.id === task.id ? { ...t, my_day: false } : t)),
          );
          this.notificationService.error('加入 My Day 失敗');
        },
      });
  }

  protected toggleCreateForm(): void {
    this.isCreating.update((v) => !v);
    if (!this.isCreating()) {
      this.newTaskTitle.set('');
    }
  }

  protected createTask(): void {
    const title = this.newTaskTitle().trim();
    if (!title) return;

    this.taskService
      .create({ title, my_day: true })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success(`建立「${title}」`);
          this.newTaskTitle.set('');
          this.isCreating.set(false);
          this.reloadTasks();
        },
        error: () => {
          this.notificationService.error('建立任務失敗');
        },
      });
  }

  // --- Insight Actions ---

  protected verifyInsight(insight: ApiInsight): void {
    this.updateInsightStatus(insight, 'verified');
  }

  protected invalidateInsight(insight: ApiInsight): void {
    this.updateInsightStatus(insight, 'invalidated');
  }

  protected showEvidenceInput(insightId: number): void {
    this.evidenceTarget.set(insightId);
    this.evidenceText.set('');
  }

  protected cancelEvidence(): void {
    this.evidenceTarget.set(null);
    this.evidenceText.set('');
  }

  protected submitEvidence(): void {
    const id = this.evidenceTarget();
    const text = this.evidenceText().trim();
    if (id === null || !text) return;

    this.insightService
      .update(id, { append_evidence: text })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('已補充 evidence');
          this.cancelEvidence();
          this.reloadInsights();
        },
        error: () => {
          this.notificationService.error('補充 evidence 失敗');
        },
      });
  }

  // --- Helpers ---

  private completionRate(note: ApiSessionNote): number {
    return ((note.metadata as Record<string, number> | null)?.['completion_rate'] ?? 0) * 100;
  }

  private updateInsightStatus(insight: ApiInsight, status: 'verified' | 'invalidated'): void {
    this.insights.update((list) => list.filter((i) => i.id !== insight.id));

    this.insightService
      .update(insight.id, { status })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          const label = status === 'verified' ? '已驗證' : '已否決';
          this.notificationService.success(`Insight ${label}`);
        },
        error: () => {
          this.insights.update((list) => [...list, insight]);
          this.notificationService.error('更新 insight 失敗');
        },
      });
  }

  private loadData(): void {
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

    forkJoin({
      tasks: this.taskService.list(),
      notes: this.sessionNoteService.list(yesterday, undefined, 2),
      metrics: this.sessionNoteService.list(undefined, 'metrics', 7),
      insights: this.insightService.list({ status: 'unverified', limit: 5 }),
      summary: this.taskService.dailySummary(),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ tasks, notes, metrics, insights, summary }) => {
          this.tasks.set(tasks);
          this.sessionNotes.set(notes);
          this.metricsNotes.set(metrics);
          this.insights.set(insights.insights);
          this.unverifiedCount.set(insights.unverified_count);
          this.dailySummary.set(summary);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入今日資料');
          this.isLoading.set(false);
        },
      });
  }

  private reloadTasks(): void {
    this.taskService
      .list()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({ next: (tasks) => this.tasks.set(tasks) });
  }

  private reloadInsights(): void {
    this.insightService
      .list({ status: 'unverified', limit: 5 })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this.insights.set(result.insights);
          this.unverifiedCount.set(result.unverified_count);
        },
      });
  }

  private refreshSummary(): void {
    this.taskService
      .dailySummary()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({ next: (summary) => this.dailySummary.set(summary) });
  }
}
