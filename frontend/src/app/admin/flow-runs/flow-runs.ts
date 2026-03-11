import {
  Component,
  DestroyRef,
  inject,
  signal,
  computed,
  ChangeDetectionStrategy,
  OnInit,
  OnDestroy,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { DatePipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ArrowLeft,
  Activity,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  ChevronLeft,
  ChevronRight,
  Eye,
  RotateCcw,
  Filter,
  X,
} from 'lucide-angular';
import {
  FlowRunService,
  FlowRunFilters,
} from '../../core/services/flow-run.service';
import { PipelineService } from '../../core/services/pipeline.service';
import type { ApiFlowRun, FlowRunStatus } from '../../core/models';
import { NotificationService } from '../../core/services/notification.service';

const RUNS_PER_PAGE = 20;

const STATUS_CONFIG: Record<FlowRunStatus, { label: string; classes: string }> = {
  pending: {
    label: 'Pending',
    classes: 'border-zinc-600 bg-zinc-800 text-zinc-300',
  },
  running: {
    label: 'Running',
    classes: 'border-sky-700 bg-sky-900/30 text-sky-400',
  },
  completed: {
    label: 'Completed',
    classes: 'border-emerald-700 bg-emerald-900/30 text-emerald-400',
  },
  failed: {
    label: 'Failed',
    classes: 'border-red-700 bg-red-900/30 text-red-400',
  },
};

const ALL_FLOW_NAMES = [
  'content-review',
  'content-polish',
  'collect-and-score',
  'digest-generate',
  'bookmark-generate',
  'notion-sync',
  'morning-brief',
  'weekly-review',
  'project-track',
  'content-strategy',
  'build-log-generate',
  'goal-sync',
] as const;

const FLOW_NAME_LABELS: Record<string, string> = {
  'content-review': 'Content Review',
  'content-polish': 'Content Polish',
  'collect-and-score': 'Collect & Score',
  'digest-generate': 'Digest Generate',
  'bookmark-generate': 'Bookmark Generate',
  'notion-sync': 'Notion Sync',
  'morning-brief': 'Morning Brief',
  'weekly-review': 'Weekly Review',
  'project-track': 'Project Track',
  'content-strategy': 'Content Strategy',
  'build-log-generate': 'Build Log Generate',
  'goal-sync': 'Goal Sync',
};

@Component({
  selector: 'app-flow-runs',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './flow-runs.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FlowRunsComponent implements OnInit, OnDestroy {
  private readonly flowRunService = inject(FlowRunService);
  private readonly pipelineService = inject(PipelineService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly notificationService = inject(NotificationService);
  private autoRefreshTimer: ReturnType<typeof setInterval> | null = null;

  protected readonly runs = signal<ApiFlowRun[]>([]);
  protected readonly totalRuns = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly statusFilter = signal<FlowRunStatus | null>(null);
  protected readonly flowNameFilter = signal<string | null>(null);
  protected readonly expandedRunId = signal<string | null>(null);
  protected readonly isAutoRefresh = signal(false);

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalRuns() / RUNS_PER_PAGE),
  );
  protected readonly pageArray = computed(() =>
    Array.from({ length: this.totalPages() }, (_, i) => i + 1),
  );
  protected readonly triggering = this.pipelineService.triggering;

  protected readonly allFlowNames = ALL_FLOW_NAMES;

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly ActivityIcon = Activity;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly CheckCircle2Icon = CheckCircle2;
  protected readonly XCircleIcon = XCircle;
  protected readonly ClockIcon = Clock;
  protected readonly Loader2Icon = Loader2;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly EyeIcon = Eye;
  protected readonly RotateCcwIcon = RotateCcw;
  protected readonly retryingId = signal<string | null>(null);
  protected readonly FilterIcon = Filter;
  protected readonly XIcon = X;

  ngOnInit(): void {
    this.loadRuns();
  }

  protected loadRuns(): void {
    this.isLoading.set(true);
    this.error.set(null);

    const filters: FlowRunFilters = {
      page: this.currentPage(),
      perPage: RUNS_PER_PAGE,
    };
    const status = this.statusFilter();
    if (status) {
      filters.status = status;
    }
    const flowName = this.flowNameFilter();
    if (flowName) {
      filters.flowName = flowName;
    }

    this.flowRunService
      .getFlowRuns(filters)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.runs.set(response.data);
          this.totalRuns.set(response.meta.total);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('無法載入 Flow Runs');
          this.isLoading.set(false);
        },
      });
  }

  protected onStatusFilter(status: FlowRunStatus | null): void {
    this.statusFilter.set(status);
    this.currentPage.set(1);
    this.loadRuns();
  }

  protected onFlowNameFilter(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    this.flowNameFilter.set(value || null);
    this.currentPage.set(1);
    this.loadRuns();
  }

  protected toggleAutoRefresh(): void {
    if (this.isAutoRefresh()) {
      this.stopAutoRefresh();
    } else {
      this.startAutoRefresh();
    }
  }

  ngOnDestroy(): void {
    this.stopAutoRefresh();
  }

  private startAutoRefresh(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }
    this.isAutoRefresh.set(true);
    this.autoRefreshTimer = setInterval(() => this.loadRuns(), 10000);
  }

  private stopAutoRefresh(): void {
    this.isAutoRefresh.set(false);
    if (this.autoRefreshTimer !== null) {
      clearInterval(this.autoRefreshTimer);
      this.autoRefreshTimer = null;
    }
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    this.loadRuns();
  }

  protected toggleExpand(runId: string): void {
    this.expandedRunId.set(
      this.expandedRunId() === runId ? null : runId,
    );
  }

  protected triggerSync(): void {
    this.pipelineService
      .triggerSync()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.notificationService.success('Obsidian 同步已觸發'),
        error: () => this.notificationService.error('同步觸發失敗'),
      });
  }

  protected triggerCollect(): void {
    this.pipelineService
      .triggerCollect()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notificationService.success('RSS 收集已觸發');
          this.loadRuns();
        },
        error: () => this.notificationService.error('收集觸發失敗'),
      });
  }

  protected retryRun(runId: string): void {
    this.retryingId.set(runId);
    this.flowRunService
      .retryFlowRun(runId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.retryingId.set(null);
          this.notificationService.success('重試已觸發');
          this.loadRuns();
        },
        error: () => {
          this.retryingId.set(null);
          this.notificationService.error('重試觸發失敗');
        },
      });
  }

  protected getStatusConfig(status: FlowRunStatus): { label: string; classes: string } {
    return STATUS_CONFIG[status];
  }

  protected getFlowLabel(flowName: string): string {
    return FLOW_NAME_LABELS[flowName] ?? flowName;
  }

  protected getDuration(run: ApiFlowRun): string | null {
    if (!run.started_at || !run.ended_at) {
      return null;
    }
    const ms = new Date(run.ended_at).getTime() - new Date(run.started_at).getTime();
    if (ms < 1000) {
      return `${ms}ms`;
    }
    return `${(ms / 1000).toFixed(1)}s`;
  }

  protected formatJson(data: Record<string, unknown> | null): string {
    if (!data) {
      return '—';
    }
    return JSON.stringify(data, null, 2);
  }

}
