import {
  Component,
  ChangeDetectionStrategy,
  inject,
  computed,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { LucideAngularModule, Clock, ChevronRight } from 'lucide-angular';
import { catchError, map, of, startWith } from 'rxjs';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type { LearningDashboard } from '../../core/models/admin.model';

interface DashboardState {
  data: LearningDashboard | null;
  isLoading: boolean;
}

@Component({
  selector: 'app-session-history',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './session-history.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SessionHistoryComponent {
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);

  private readonly state = toSignal(
    this.learnService.getDashboard().pipe(
      map((data): DashboardState => ({ data, isLoading: false })),
      catchError(() => {
        this.notificationService.error('Failed to load sessions');
        return of<DashboardState>({ data: null, isLoading: false });
      }),
      startWith<DashboardState>({ data: null, isLoading: true }),
    ),
    { requireSync: true },
  );

  protected readonly sessions = computed(
    () => this.state().data?.recent_sessions ?? [],
  );
  protected readonly isLoading = computed(() => this.state().isLoading);

  protected readonly ClockIcon = Clock;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly DOMAIN_COLORS: Record<string, string | undefined> = {
    leetcode: 'bg-violet-900/40 text-violet-400 border-violet-800/50',
    japanese: 'bg-sky-900/40 text-sky-400 border-sky-800/50',
    'system-design': 'bg-emerald-900/40 text-emerald-400 border-emerald-800/50',
    go: 'bg-amber-900/40 text-amber-400 border-amber-800/50',
  };

  protected getDomainColor(domain: string): string {
    return (
      this.DOMAIN_COLORS[domain] ??
      'bg-zinc-800/40 text-zinc-400 border-zinc-700/50'
    );
  }
}
