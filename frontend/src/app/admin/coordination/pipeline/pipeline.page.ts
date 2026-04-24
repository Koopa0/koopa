import { HttpErrorResponse } from '@angular/common/http';
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import type {
  ProcessRun,
  ProcessRunStatus,
  ProcessRunsResponse,
  StageCellState,
} from '../../../core/models/process-run.model';
import { ProcessRunService } from '../../../core/services/process-run.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

type StatusFilter = 'all' | ProcessRunStatus;

const STATUS_CHIPS: readonly { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'skipped', label: 'Skipped' },
  { value: 'pending', label: 'Pending' },
];

const STATUS_DOT: Record<ProcessRunStatus, string> = {
  pending: 'bg-zinc-400',
  running: 'bg-sky-400',
  completed: 'bg-emerald-500',
  failed: 'bg-red-500',
  skipped: 'bg-zinc-600',
};

const STATUS_TEXT: Record<ProcessRunStatus, string> = {
  pending: 'text-zinc-300',
  running: 'text-sky-300',
  completed: 'text-emerald-300',
  failed: 'text-red-300',
  skipped: 'text-zinc-500',
};

/**
 * Process runs pipeline view. Summary cards · per-stage aggregates ·
 * runs table · failures panel. The backend assembles every
 * aggregate — the component only renders.
 */
@Component({
  selector: 'app-pipeline-page',
  standalone: true,
  imports: [],
  templateUrl: './pipeline.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class PipelinePageComponent {
  private readonly processRunService = inject(ProcessRunService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusChips = STATUS_CHIPS;
  protected readonly statusFilter = signal<StatusFilter>('all');

  protected readonly resource = rxResource<ProcessRunsResponse, StatusFilter>({
    params: () => this.statusFilter(),
    stream: ({ params }) =>
      this.processRunService.list({
        status: params === 'all' ? undefined : params,
      }),
  });

  protected readonly vm = computed(() => this.resource.value());
  protected readonly summary = computed(() => this.vm()?.summary);
  // `stages` is always `[]`. The field
  // maps to scheduler-level stage labels (crawl / classify / draft /
  // grade) which aren't represented anywhere on `process_runs` yet —
  // `kind` is the run source, `name` is the run identity, neither
  // aggregates to pipeline-stage health. Populating it needs either a
  // `process_runs.stage` column or a `metadata.stage` convention
  // written by each scheduler job. The template hides the Stages panel
  // entirely while the array is empty, so there's no placeholder
  // render path to maintain.
  protected readonly stages = computed(() => this.vm()?.stages ?? []);
  protected readonly runs = computed(() => this.vm()?.runs ?? []);
  protected readonly failures = computed(() =>
    this.runs().filter((r) => r.status === 'failed'),
  );

  protected readonly total = computed(() => this.vm()?.total ?? 0);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.vm(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly endpointsUnavailable = computed(() => {
    if (this.resource.status() !== 'error') return false;
    const err = this.resource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  constructor() {
    this.topbar.set({
      title: 'Process runs',
      crumbs: ['Coordination', 'Process runs'],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setStatusFilter(value: StatusFilter): void {
    this.statusFilter.set(value);
  }

  protected statusDot(s: ProcessRunStatus): string {
    return STATUS_DOT[s];
  }

  protected statusText(s: ProcessRunStatus): string {
    return STATUS_TEXT[s];
  }

  protected cellStateClass(state: StageCellState): string {
    switch (state) {
      case 'warn':
        return 'text-amber-300';
      case 'error':
        return 'text-red-300';
      case 'ok':
        return 'text-emerald-300';
      default:
        return 'text-zinc-400';
    }
  }

  protected summaryStateClass(state: 'ok' | 'warn' | 'error'): string {
    switch (state) {
      case 'warn':
        return 'text-amber-300';
      case 'error':
        return 'text-red-300';
      case 'ok':
      default:
        return 'text-emerald-300';
    }
  }

  protected describe(run: ProcessRun): string {
    const parts: string[] = [];
    if (run.subsystem) parts.push(run.subsystem);
    if (run.source) parts.push(run.source);
    return parts.join(' · ');
  }
}
