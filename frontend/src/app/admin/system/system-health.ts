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
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Rss,
  Activity,
  Brain,
  Database,
  AlertTriangle,
  CheckCircle,
  ArrowRight,
  Clock,
} from 'lucide-angular';
import { SystemService } from '../../core/services/system.service';
import { NotificationService } from '../../core/services/notification.service';
import type { SystemHealth } from '../../core/models/admin.model';

@Component({
  selector: 'app-system-health',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './system-health.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SystemHealthComponent implements OnInit {
  private readonly systemService = inject(SystemService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly health = signal<SystemHealth | null>(null);
  protected readonly isLoading = signal(true);

  // Feed 衍生狀態
  protected readonly feedSummary = computed(() => {
    const h = this.health();
    if (!h) return null;
    return h.feeds;
  });
  protected readonly feedHealthPercent = computed(() => {
    const f = this.feedSummary();
    if (!f || f.total === 0) return 0;
    return Math.round((f.healthy / f.total) * 100);
  });

  // Pipeline 衍生狀態
  protected readonly pipelines = computed(
    () => this.health()?.pipelines ?? null,
  );
  protected readonly isPipelineHealthy = computed(() => {
    const p = this.pipelines();
    return p !== null && p.failed === 0;
  });

  // AI Budget 衍生狀態
  protected readonly aiBudget = computed(
    () => this.health()?.ai_budget ?? null,
  );
  protected readonly budgetPercent = computed(() => {
    const b = this.aiBudget();
    if (!b || b.daily_limit === 0) return 0;
    return Math.round((b.today_tokens / b.daily_limit) * 100);
  });
  protected readonly budgetColor = computed(() => {
    const pct = this.budgetPercent();
    if (pct >= 90) return 'bg-red-500';
    if (pct >= 70) return 'bg-amber-500';
    return 'bg-emerald-500';
  });
  protected readonly budgetTextColor = computed(() => {
    const pct = this.budgetPercent();
    if (pct >= 90) return 'text-red-400';
    if (pct >= 70) return 'text-amber-400';
    return 'text-emerald-400';
  });

  // Database 衍生狀態
  protected readonly database = computed(() => this.health()?.database ?? null);

  // Lucide icons
  protected readonly RssIcon = Rss;
  protected readonly ActivityIcon = Activity;
  protected readonly BrainIcon = Brain;
  protected readonly DatabaseIcon = Database;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly CheckCircleIcon = CheckCircle;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ClockIcon = Clock;

  ngOnInit(): void {
    this.loadHealth();
  }

  private loadHealth(): void {
    this.isLoading.set(true);
    this.systemService
      .getHealth()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.health.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('無法載入系統狀態');
        },
      });
  }

  protected formatTokenCount(tokens: number): string {
    if (tokens >= 1000) {
      return `${(tokens / 1000).toFixed(1)}k`;
    }
    return tokens.toString();
  }
}
