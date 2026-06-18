import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChildren,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { AgentService } from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  Agent,
  AgentStatus,
} from '../../../../core/models/workbench.model';

type StatusFilter = 'all' | AgentStatus;

const STATUS_CHIPS: readonly { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'retired', label: 'Retired' },
];

/**
 * Agents list — a read-only roster over the registry projection
 * (GET /api/admin/system/agents returns a bare []Agent). Columns:
 * Name / Platform / Schedule / Status. Row click opens the agent profile;
 * the status filter gates by active / retired (the only real dimension —
 * there is no activity or task state).
 */
@Component({
  selector: 'app-agents-list-page',
  imports: [DataTableComponent],
  templateUrl: './agents-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class AgentsListPageComponent {
  private readonly agentService = inject(AgentService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusChips = STATUS_CHIPS;
  protected readonly statusFilter = signal<StatusFilter>('all');

  protected readonly resource = rxResource<Agent[], void>({
    stream: () => this.agentService.list(),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives
  // the error banner; without this guard a failed list read throws here.
  protected readonly allAgents = computed(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );

  protected readonly rows = computed(() => {
    const filter = this.statusFilter();
    if (filter === 'all') return this.allAgents();
    return this.allAgents().filter((a) => a.status === filter);
  });

  protected readonly total = computed(() => this.rows().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && this.rows().length === 0,
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    this.topbar.set({
      title: 'Agents',
      crumbs: ['System', 'Agents'],
    });

    effect(() => {
      const idx = this.focusedIndex();
      const target = this.rowRefs()[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setStatusFilter(value: StatusFilter): void {
    this.statusFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: Agent): void {
    this.router.navigate(['/admin/system/agents', row.name]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected scheduleSummary(agent: Agent): string {
    return agent.schedule?.purpose || agent.schedule?.name || '—';
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (isFormControl(event.target)) return;
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;

    const rows = this.rows();
    if (rows.length === 0) return;

    if (event.key === 'j') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.min(i + 1, rows.length - 1));
    } else if (event.key === 'k') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.max(i - 1, 0));
    }
  }
}

function isFormControl(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target.isContentEditable
  );
}
