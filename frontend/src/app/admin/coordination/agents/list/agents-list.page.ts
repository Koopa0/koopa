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
  AgentActivityState,
  AgentSummary,
  AgentsResponse,
} from '../../../../core/models/workbench.model';

type StateFilter = 'all' | AgentActivityState | 'retired';

const STATE_CHIPS: readonly { value: StateFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'idle', label: 'Idle' },
  { value: 'blocked', label: 'Blocked' },
  { value: 'retired', label: 'Retired' },
];

const ACTIVITY_DOT_CLASS: Record<AgentActivityState, string> = {
  active: 'bg-emerald-500',
  idle: 'bg-zinc-400',
  blocked: 'bg-red-500',
};

const ACTIVITY_TEXT_CLASS: Record<AgentActivityState, string> = {
  active: 'text-emerald-300',
  idle: 'text-zinc-300',
  blocked: 'text-red-300',
};

/**
 * Agents list. Columns: Name / Platform / Activity / As creator / As
 * assignee / Status. Row click opens the agent profile; filter chips
 * gate by activity_state (or retired).
 */
@Component({
  selector: 'app-agents-list-page',
  standalone: true,
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

  protected readonly stateChips = STATE_CHIPS;
  protected readonly stateFilter = signal<StateFilter>('all');

  protected readonly resource = rxResource<AgentsResponse, void>({
    stream: () => this.agentService.list(),
  });

  protected readonly envelope = computed(() => this.resource.value());
  protected readonly allAgents = computed(() => this.envelope()?.agents ?? []);

  protected readonly rows = computed(() => {
    const filter = this.stateFilter();
    return this.allAgents().filter((a) => {
      if (filter === 'all') return true;
      if (filter === 'retired') return a.status === 'retired';
      return a.status === 'active' && a.activity_state === filter;
    });
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
      crumbs: ['Coordination', 'Agents'],
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

  protected setStateFilter(value: StateFilter): void {
    this.stateFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: AgentSummary): void {
    this.router.navigate(['/admin/coordination/agents', row.name]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected activityDotClass(state: AgentActivityState): string {
    return ACTIVITY_DOT_CLASS[state];
  }

  protected activityTextClass(state: AgentActivityState): string {
    return ACTIVITY_TEXT_CLASS[state];
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
