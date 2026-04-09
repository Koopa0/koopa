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
  BarChart3,
  TrendingUp,
  TrendingDown,
  Minus,
  Target,
  Brain,
  FileText,
  Inbox,
  AlertTriangle,
  Send,
} from 'lucide-angular';
import { DashboardService } from '../../core/services/dashboard.service';
import { NotificationService } from '../../core/services/notification.service';
import type { DashboardTrends } from '../../core/models/admin.model';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './dashboard.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardComponent implements OnInit {
  private readonly dashboardService = inject(DashboardService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly trends = signal<DashboardTrends | null>(null);
  protected readonly isLoading = signal(true);

  // Derived state
  protected readonly period = computed(() => this.trends()?.period ?? '');
  protected readonly execution = computed(
    () => this.trends()?.execution ?? null,
  );
  protected readonly planAdherence = computed(
    () => this.trends()?.plan_adherence ?? null,
  );
  protected readonly goalHealth = computed(
    () => this.trends()?.goal_health ?? null,
  );
  protected readonly learning = computed(() => this.trends()?.learning ?? null);
  protected readonly content = computed(() => this.trends()?.content ?? null);
  protected readonly inboxHealth = computed(
    () => this.trends()?.inbox_health ?? null,
  );
  protected readonly somedayHealth = computed(
    () => this.trends()?.someday_health ?? null,
  );
  protected readonly directiveHealth = computed(
    () => this.trends()?.directive_health ?? null,
  );

  // Summary numbers
  protected readonly summaryItems = computed(() => {
    const t = this.trends();
    if (!t) return [];
    return [
      {
        label: 'Tasks Completed',
        value: t.execution.tasks_completed_this_week,
      },
      {
        label: 'Plan Adherence',
        value: t.plan_adherence.completion_rate_this_week,
        suffix: '%',
      },
      { label: 'Published This Month', value: t.content.published_this_month },
      { label: 'Review Backlog', value: t.learning.review_backlog },
    ];
  });

  protected readonly inboxNetChange = computed(() => {
    const ih = this.inboxHealth();
    if (!ih) return 0;
    return ih.current_count - ih.week_start_count;
  });

  protected readonly contentProgress = computed(() => {
    const c = this.content();
    if (!c || c.published_target === 0) return 0;
    return Math.round((c.published_this_month / c.published_target) * 100);
  });

  // Icons
  protected readonly BarChart3Icon = BarChart3;
  protected readonly TrendingUpIcon = TrendingUp;
  protected readonly TrendingDownIcon = TrendingDown;
  protected readonly MinusIcon = Minus;
  protected readonly TargetIcon = Target;
  protected readonly BrainIcon = Brain;
  protected readonly FileTextIcon = FileText;
  protected readonly InboxIcon = Inbox;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly SendIcon = Send;

  ngOnInit(): void {
    this.loadTrends();
  }

  private loadTrends(): void {
    this.isLoading.set(true);
    this.dashboardService
      .getDashboardTrends()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.trends.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load trends dashboard');
        },
      });
  }
}
