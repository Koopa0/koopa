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
import { RouterLink } from '@angular/router';
import { LucideAngularModule, BookOpen, ChevronRight } from 'lucide-angular';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type { LearningPlanSummary } from '../../core/models/admin.model';

@Component({
  selector: 'app-plans-list',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './plans-list.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PlansListComponent implements OnInit {
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly plans = signal<LearningPlanSummary[]>([]);
  protected readonly isLoading = signal(true);

  protected readonly activePlans = computed(() =>
    this.plans().filter((p) => p.status === 'active'),
  );
  protected readonly otherPlans = computed(() =>
    this.plans().filter((p) => p.status !== 'active'),
  );

  protected readonly BookOpenIcon = BookOpen;
  protected readonly ChevronRightIcon = ChevronRight;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    draft: 'text-zinc-400 bg-zinc-800/50 border-zinc-700',
    active: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    paused: 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    completed: 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    abandoned: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  protected readonly DOMAIN_COLORS: Record<string, string | undefined> = {
    leetcode: 'bg-violet-900/40 text-violet-400 border-violet-800/50',
    japanese: 'bg-sky-900/40 text-sky-400 border-sky-800/50',
    'system-design': 'bg-emerald-900/40 text-emerald-400 border-emerald-800/50',
    go: 'bg-amber-900/40 text-amber-400 border-amber-800/50',
  };

  ngOnInit(): void {
    this.loadPlans();
  }

  private loadPlans(): void {
    this.isLoading.set(true);
    this.learnService
      .getPlans()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.plans.set(data.plans);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load learning plans');
        },
      });
  }

  protected getProgressPercent(plan: LearningPlanSummary): number {
    if (plan.items_total === 0) return 0;
    return Math.round((plan.items_completed / plan.items_total) * 100);
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }

  protected getDomainColor(domain: string): string {
    return (
      this.DOMAIN_COLORS[domain] ??
      'bg-zinc-800/40 text-zinc-400 border-zinc-700/50'
    );
  }
}
