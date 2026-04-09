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
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  BookOpen,
  Check,
  SkipForward,
  ArrowRightLeft,
  Circle,
} from 'lucide-angular';
import { LearnService } from '../../core/services/learn.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  LearningPlanDetail,
  PlanItemDetail,
} from '../../core/models/admin.model';

@Component({
  selector: 'app-plan-detail',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './plan-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PlanDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly learnService = inject(LearnService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly plan = signal<LearningPlanDetail | null>(null);
  protected readonly isLoading = signal(true);

  protected readonly progress = computed(
    () =>
      this.plan()?.progress ?? {
        total: 0,
        completed: 0,
        skipped: 0,
        substituted: 0,
        planned: 0,
      },
  );

  protected readonly items = computed(() => this.plan()?.items ?? []);

  protected readonly progressPercent = computed(() => {
    const p = this.progress();
    if (p.total === 0) return 0;
    return Math.round((p.completed / p.total) * 100);
  });

  // Icons
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly CheckIcon = Check;
  protected readonly SkipForwardIcon = SkipForward;
  protected readonly ArrowRightLeftIcon = ArrowRightLeft;
  protected readonly CircleIcon = Circle;

  protected readonly STATUS_COLORS: Record<string, string | undefined> = {
    draft: 'text-zinc-400 bg-zinc-800/50 border-zinc-700',
    active: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/30',
    paused: 'text-amber-400 bg-amber-950/30 border-amber-800/30',
    completed: 'text-sky-400 bg-sky-950/30 border-sky-800/30',
    abandoned: 'text-zinc-500 bg-zinc-800/30 border-zinc-700/30',
  };

  protected readonly ITEM_STATUS_ICONS: Record<
    string,
    typeof Check | typeof SkipForward | typeof ArrowRightLeft | typeof Circle
  > = {
    completed: Check,
    skipped: SkipForward,
    substituted: ArrowRightLeft,
    planned: Circle,
  };

  protected readonly ITEM_STATUS_COLORS: Record<string, string | undefined> = {
    completed: 'text-emerald-500',
    skipped: 'text-zinc-500',
    substituted: 'text-amber-500',
    planned: 'text-zinc-700',
  };

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.loadPlan(id);
    }
  }

  private loadPlan(id: string): void {
    this.isLoading.set(true);
    this.learnService
      .getPlanDetail(id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.plan.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load plan');
        },
      });
  }

  protected getItemStatusIcon(
    item: PlanItemDetail,
  ): typeof Check | typeof SkipForward | typeof ArrowRightLeft | typeof Circle {
    return this.ITEM_STATUS_ICONS[item.status] ?? Circle;
  }

  protected getItemStatusColor(item: PlanItemDetail): string {
    return this.ITEM_STATUS_COLORS[item.status] ?? 'text-zinc-700';
  }

  protected getStatusColor(status: string): string {
    return (
      this.STATUS_COLORS[status] ??
      'text-zinc-400 bg-zinc-800/50 border-zinc-700'
    );
  }
}
