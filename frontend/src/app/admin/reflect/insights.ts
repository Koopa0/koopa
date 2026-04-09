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
  Lightbulb,
  CheckCircle,
  XCircle,
  Clock,
  CircleDot,
} from 'lucide-angular';
import { ReflectService } from '../../core/services/reflect.service';
import { NotificationService } from '../../core/services/notification.service';
import type { InsightCheck } from '../../core/models/admin.model';

type InsightFilter = 'all' | 'unverified' | 'verified' | 'invalidated';

@Component({
  selector: 'app-insights',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './insights.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InsightsComponent implements OnInit {
  private readonly reflectService = inject(ReflectService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly insights = signal<InsightCheck[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly activeFilter = signal<InsightFilter>('all');

  protected readonly filteredInsights = computed(() => {
    const filter = this.activeFilter();
    if (filter === 'all') return this.insights();
    return this.insights().filter((i) => i.status === filter);
  });

  protected readonly filterTabs: { key: InsightFilter; label: string }[] = [
    { key: 'all', label: 'All' },
    { key: 'unverified', label: 'Unverified' },
    { key: 'verified', label: 'Verified' },
    { key: 'invalidated', label: 'Invalidated' },
  ];

  // Lucide icons
  protected readonly LightbulbIcon = Lightbulb;
  protected readonly CheckCircleIcon = CheckCircle;
  protected readonly XCircleIcon = XCircle;
  protected readonly ClockIcon = Clock;
  protected readonly CircleDotIcon = CircleDot;

  ngOnInit(): void {
    this.loadInsights();
  }

  private loadInsights(): void {
    this.isLoading.set(true);
    this.reflectService
      .getInsights()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.insights.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load insights');
        },
      });
  }

  protected setFilter(filter: InsightFilter): void {
    this.activeFilter.set(filter);
  }

  protected getStatusClasses(status: string): string {
    const classes: Record<string, string> = {
      unverified: 'bg-amber-900/40 text-amber-400',
      verified: 'bg-emerald-900/40 text-emerald-400',
      invalidated: 'bg-red-900/40 text-red-400',
      archived: 'bg-zinc-800 text-zinc-500',
    };
    return classes[status] ?? classes['archived'];
  }

  protected getStatusLabel(status: string): string {
    const labels: Record<string, string> = {
      unverified: 'Unverified',
      verified: 'Verified',
      invalidated: 'Invalidated',
      archived: 'Archived',
    };
    return labels[status] ?? status;
  }

  protected getStatusIcon(status: string): typeof Lightbulb {
    switch (status) {
      case 'verified':
        return CheckCircle;
      case 'invalidated':
        return XCircle;
      default:
        return CircleDot;
    }
  }
}
