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
import { DatePipe } from '@angular/common';
import { LucideAngularModule, Clock, ChevronRight } from 'lucide-angular';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  LearningDashboard,
  SessionSummary,
} from '../../core/models/admin.model';

@Component({
  selector: 'app-session-history',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './session-history.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SessionHistoryComponent implements OnInit {
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly dashboard = signal<LearningDashboard | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly sessions = computed(
    () => this.dashboard()?.recent_sessions ?? [],
  );

  protected readonly ClockIcon = Clock;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly DOMAIN_COLORS: Record<string, string | undefined> = {
    leetcode: 'bg-violet-900/40 text-violet-400 border-violet-800/50',
    japanese: 'bg-sky-900/40 text-sky-400 border-sky-800/50',
    'system-design': 'bg-emerald-900/40 text-emerald-400 border-emerald-800/50',
    go: 'bg-amber-900/40 text-amber-400 border-amber-800/50',
  };

  ngOnInit(): void {
    this.loadSessions();
  }

  private loadSessions(): void {
    this.isLoading.set(true);
    this.learnService
      .getDashboard()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.dashboard.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load sessions');
        },
      });
  }

  protected getDomainColor(domain: string): string {
    return (
      this.DOMAIN_COLORS[domain] ??
      'bg-zinc-800/40 text-zinc-400 border-zinc-700/50'
    );
  }

  protected getSuccessRatio(session: SessionSummary): string {
    return `${session.solved_count}/${session.attempts_count}`;
  }
}
