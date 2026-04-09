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
  Check,
  Clock,
  ArrowRight,
  Inbox,
  FileText,
  BookOpen,
  GitCommit,
  Send,
  Pause,
  X,
} from 'lucide-angular';
import { ReflectService } from '../../core/services/reflect.service';
import { NotificationService } from '../../core/services/notification.service';
import type { DailyReflectionContext } from '../../core/models/admin.model';

@Component({
  selector: 'app-daily-review',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './daily-review.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DailyReviewComponent implements OnInit {
  private readonly reflectService = inject(ReflectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly context = signal<DailyReflectionContext | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly journalText = signal('');
  protected readonly isSaving = signal(false);

  // Derived state
  protected readonly planVsActual = computed(
    () => this.context()?.plan_vs_actual ?? null,
  );
  protected readonly completedTasks = computed(
    () => this.context()?.completed_tasks ?? [],
  );
  protected readonly learningSessions = computed(
    () => this.context()?.learning_sessions ?? [],
  );
  protected readonly contentChanges = computed(
    () => this.context()?.content_changes ?? [],
  );
  protected readonly commitsCount = computed(
    () => this.context()?.commits_count ?? 0,
  );
  protected readonly inboxDelta = computed(
    () => this.context()?.inbox_delta ?? null,
  );

  protected readonly summaryLine = computed(() => {
    const pva = this.planVsActual();
    if (!pva) return '';
    const parts: string[] = [`${pva.planned} planned`];
    parts.push(`${pva.completed} completed`);
    if (pva.deferred > 0) parts.push(`${pva.deferred} deferred`);
    if (pva.dropped > 0) parts.push(`${pva.dropped} dropped`);
    return parts.join(' · ');
  });

  protected readonly AREA_CLASSES: Record<string, string | undefined> = {
    backend: 'bg-violet-900/40 text-violet-400',
    learning: 'bg-sky-900/40 text-sky-400',
    studio: 'bg-amber-900/40 text-amber-400',
    career: 'bg-emerald-900/40 text-emerald-400',
    frontend: 'bg-blue-900/40 text-blue-400',
    ops: 'bg-orange-900/40 text-orange-400',
  };

  // Lucide icons
  protected readonly CheckIcon = Check;
  protected readonly ClockIcon = Clock;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly InboxIcon = Inbox;
  protected readonly FileTextIcon = FileText;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly GitCommitIcon = GitCommit;
  protected readonly SendIcon = Send;
  protected readonly PauseIcon = Pause;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadContext();
  }

  private loadContext(): void {
    this.isLoading.set(true);
    this.reflectService
      .getDailyContext()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.context.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load daily review');
        },
      });
  }

  protected updateJournalText(event: Event): void {
    const target = event.target as HTMLTextAreaElement;
    this.journalText.set(target.value);
  }

  protected saveReflection(): void {
    const text = this.journalText().trim();
    if (!text) return;

    this.isSaving.set(true);
    this.reflectService
      .writeJournal({ kind: 'reflection', body: text })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isSaving.set(false);
          this.journalText.set('');
          this.notificationService.success('Reflection saved');
        },
        error: () => {
          this.isSaving.set(false);
          this.notificationService.error('Failed to save');
        },
      });
  }
}
