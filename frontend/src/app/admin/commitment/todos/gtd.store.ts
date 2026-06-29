import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { of, switchMap, type Observable } from 'rxjs';
import {
  TodoService,
  type RecurrenceRequest,
  type TodoAdvanceAction,
  type TodoItem,
  type TodoRow,
} from '../../../core/services/todo.service';
import {
  DailyPlanService,
  type DailyPlan,
} from '../../../core/services/daily-plan.service';
import { NotificationService } from '../../../core/services/notification.service';
import {
  ADVANCE_TOAST,
  advanceActionFor,
  appendToPlan,
  clarifyUpdate,
  emptyCopyFor,
  keyboardLegend,
  mutationErrorMessage,
  planMemberIds,
  recurringGroupsOf,
  rowsForView,
  viewCounts,
  type ClarifyResult,
  type GtdView,
} from './gtd-view';

const BACKLOG_PAGE_SIZE = 200;
const HISTORY_DEBOUNCE_MS = 250;

// The backlog feeds the inbox / today / pending / someday views — every
// live state, never `done`. Filtering server-side (rather than fetching
// everything and dropping done locally) keeps a long completed history from
// pushing live rows past the per_page cap.
const BACKLOG_STATES = ['inbox', 'todo', 'in_progress', 'someday'] as const;

/**
 * Why the clarify modal was opened. `clarify` lands the capture as a plain
 * todo; `pull` additionally appends it to today's plan after the inbox→todo
 * transition — the daily-plan PUT rejects inbox-state rows, so a capture
 * can't be pulled into today without clarifying first.
 */
export type ClarifyIntent = 'clarify' | 'pull';

/**
 * Page-scoped state for the GTD surface: the four data resources
 * (backlog list, daily plan, recurring buckets, completed history),
 * the active view + row selection, and every mutation round-trip
 * (capture, advance verbs, clarify, plan append). Provided by the GTD
 * page so the state dies with the route.
 */
@Injectable()
export class GtdStore {
  private readonly todoService = inject(TodoService);
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly notifications = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  readonly view = signal<GtdView>('inbox');
  readonly selectedIndex = signal(0);
  readonly clarifyTarget = signal<TodoRow | null>(null);
  readonly recurrenceTarget = signal<TodoRow | null>(null);
  private readonly clarifyIntent = signal<ClarifyIntent>('clarify');
  readonly searchDraft = signal('');
  private readonly historyQuery = signal('');
  private historyTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly _busy = signal(false);
  readonly busy = this._busy.asReadonly();

  readonly backlog = rxResource<TodoRow[], void>({
    stream: () =>
      this.todoService.list({
        state: [...BACKLOG_STATES],
        per_page: BACKLOG_PAGE_SIZE,
      }),
  });
  readonly plan = rxResource<DailyPlan, void>({
    stream: () => this.dailyPlanService.today(),
  });
  readonly recurring = rxResource({
    stream: () => this.todoService.recurring(),
  });
  readonly history = rxResource({
    params: () => ({ q: this.historyQuery() }),
    stream: ({ params }) =>
      this.todoService.history(params.q ? { q: params.q } : {}),
  });

  // Guarded snapshots: rxResource.value() throws while the resource is in an
  // error state, so gate every read on hasValue() (the repo idiom). viewError()
  // drives the error UI; without these guards a failed fetch throws and the
  // error UI is dead. Each snapshot preserves the prior fallback shape.
  private readonly planValue = computed(() =>
    this.plan.hasValue() ? this.plan.value() : undefined,
  );
  private readonly backlogValue = computed(() =>
    this.backlog.hasValue() ? this.backlog.value() : [],
  );
  private readonly historyValue = computed(() =>
    this.history.hasValue() ? this.history.value() : [],
  );
  private readonly recurringValue = computed(() =>
    this.recurring.hasValue() ? this.recurring.value() : undefined,
  );

  private readonly todayIso = new Date().toISOString().slice(0, 10);
  private readonly planIds = computed(() =>
    planMemberIds(this.planValue()?.items ?? []),
  );
  readonly rows = computed(() =>
    rowsForView(this.view(), this.backlogValue(), this.planIds(), this.todayIso),
  );
  readonly selection = computed(() =>
    Math.min(this.selectedIndex(), Math.max(this.rows().length - 1, 0)),
  );
  readonly historyRows = computed(() => this.historyValue());
  readonly recurringGroups = computed(() =>
    recurringGroupsOf(this.recurringValue()),
  );
  readonly counts = computed(() =>
    viewCounts(
      this.backlogValue(),
      this.planIds(),
      this.todayIso,
      this.recurringValue(),
      this.historyRows().length,
    ),
  );
  readonly itemCount = computed(() => this.counts()[this.view()]);
  readonly legend = computed(() => keyboardLegend(this.view()));
  readonly emptyCopy = computed(() =>
    emptyCopyFor(this.view(), this.searchDraft().trim() !== ''),
  );
  private readonly activeResource = computed(() => {
    if (this.view() === 'recurring') return this.recurring;
    if (this.view() === 'history') return this.history;
    return this.backlog;
  });
  readonly viewLoading = computed(
    () => this.activeResource().status() === 'loading',
  );
  readonly viewError = computed(
    () => this.activeResource().status() === 'error',
  );

  constructor() {
    this.destroyRef.onDestroy(() => {
      if (this.historyTimer !== null) clearTimeout(this.historyTimer);
    });
  }

  setView(view: GtdView): void {
    this.view.set(view);
    this.selectedIndex.set(0);
  }

  reloadActive(): void {
    this.activeResource().reload();
  }

  /** Debounced history search — lands in ?q= on the history endpoint. */
  searchHistory(value: string): void {
    this.searchDraft.set(value);
    if (this.historyTimer !== null) clearTimeout(this.historyTimer);
    this.historyTimer = setTimeout(
      () => this.historyQuery.set(value.trim()),
      HISTORY_DEBOUNCE_MS,
    );
  }

  /** Capture a raw thought into the inbox; lands unclarified. */
  capture(title: string, onDone: () => void): void {
    if (this._busy()) return;
    this._busy.set(true);
    this.todoService.create({ title }).subscribe({
      next: () => {
        this._busy.set(false);
        this.notifications.success('Captured to inbox');
        this.setView('inbox');
        this.backlog.reload();
        onDone();
      },
      error: () => {
        this._busy.set(false);
        this.notifications.error('Failed to capture.');
      },
    });
  }

  /** Primary advance: inbox rows open clarify, others run their verb. */
  advanceRow(row: TodoRow): void {
    if (row.state === 'inbox') {
      this.openClarify(row);
      return;
    }
    const action = advanceActionFor(row.state);
    if (action) this.runAdvance(row, action);
  }

  deferRow(row: TodoRow): void {
    this.runAdvance(row, 'defer');
  }

  dropRow(row: TodoRow): void {
    this.runAdvance(row, 'drop');
  }

  /**
   * Pull a row into today's plan. Inbox captures can't join the plan
   * directly — the daily-plan PUT rejects inbox-state rows — so 't' on an
   * inbox row opens clarify with pull intent and the append runs after the
   * inbox→todo transition (see clarified). Already-todo rows append via the
   * atomic PUT replace.
   */
  pullRow(row: TodoRow): void {
    if (row.state === 'inbox') {
      this.clarifyIntent.set('pull');
      this.clarifyTarget.set(row);
      return;
    }
    const plan = this.planValue();
    if (!plan) {
      this.notifications.error('Today’s plan has not loaded yet.');
      return;
    }
    if (this.planIds().has(row.id)) {
      this.notifications.info('Already in today’s plan.');
      return;
    }
    this.mutate(
      this.dailyPlanService.replace(appendToPlan(plan.items, row.id)),
      'Pulled into today',
      { plan: true },
    );
  }

  /** Open the clarify modal for a row with plain clarify intent. */
  openClarify(row: TodoRow): void {
    this.clarifyIntent.set('clarify');
    this.clarifyTarget.set(row);
  }

  /** Dismiss the clarify modal without acting; resets the pull intent. */
  closeClarify(): void {
    this.clarifyTarget.set(null);
    this.clarifyIntent.set('clarify');
  }

  /**
   * Clarify-modal submit: optional field PUT, then advance(clarify). When the
   * modal was opened with pull intent ('t' on an inbox row) the freshly
   * clarified todo is appended to today's plan.
   */
  clarified(result: ClarifyResult): void {
    const row = this.clarifyTarget();
    if (!row) return;
    const pull = this.clarifyIntent() === 'pull';
    this.clarifyTarget.set(null);
    this.clarifyIntent.set('clarify');
    const fields = clarifyUpdate(result);
    const update$: Observable<TodoItem | null> = fields
      ? this.todoService.update(row.id, fields)
      : of(null);
    const clarify$ = update$.pipe(
      switchMap(() => this.todoService.advance(row.id, 'clarify')),
    );
    if (pull) {
      this.runPullChain(row, clarify$);
    } else {
      this.mutate(clarify$, ADVANCE_TOAST.clarify, {});
    }
  }

  /** Open the recurrence editor for a row. */
  openRecurrence(row: TodoRow): void {
    this.recurrenceTarget.set(row);
  }

  /** Dismiss the recurrence editor without acting. */
  closeRecurrence(): void {
    this.recurrenceTarget.set(null);
  }

  /**
   * Recurrence-editor save: set or clear the row's schedule, then refresh the
   * backlog and recurring buckets so the change shows immediately. Closes the
   * editor before the round-trip so the modal unmounts cleanly.
   */
  saveRecurrence(req: RecurrenceRequest): void {
    const row = this.recurrenceTarget();
    if (!row) return;
    this.recurrenceTarget.set(null);
    const message = req.clear ? 'Recurrence cleared' : 'Routine set';
    this.mutate(this.todoService.setRecurrence(row.id, req), message, {});
    this.recurring.reload();
  }

  deferInstead(): void {
    const row = this.clarifyTarget();
    if (!row) return;
    this.clarifyTarget.set(null);
    this.clarifyIntent.set('clarify');
    this.runAdvance(row, 'defer');
  }

  /**
   * Drop the capture from the clarify dialog. Clears the target first — unlike
   * dropRow, which only advances — so the modal unmounts before the backlog
   * reload removes the row underneath it.
   */
  dropInstead(): void {
    const row = this.clarifyTarget();
    if (!row) return;
    this.clarifyTarget.set(null);
    this.clarifyIntent.set('clarify');
    this.runAdvance(row, 'drop');
  }

  // Append the freshly-clarified capture to today's plan. The plan must be
  // loaded; a stale/missing plan aborts before the clarify fires so nothing
  // half-applies. An already-planned row just clarifies (no double append).
  private runPullChain(
    row: TodoRow,
    clarify$: Observable<TodoItem | null>,
  ): void {
    const plan = this.planValue();
    if (!plan) {
      this.notifications.error('Today’s plan has not loaded yet.');
      return;
    }
    if (this.planIds().has(row.id)) {
      this.mutate(clarify$, ADVANCE_TOAST.clarify, {});
      return;
    }
    const pull$ = clarify$.pipe(
      switchMap(() =>
        this.dailyPlanService.replace(appendToPlan(plan.items, row.id)),
      ),
    );
    this.mutate(pull$, 'Pulled into today', { plan: true });
  }

  private runAdvance(row: TodoRow, action: TodoAdvanceAction): void {
    const done = action === 'complete';
    this.mutate(this.todoService.advance(row.id, action), ADVANCE_TOAST[action], {
      plan: done,
      history: done,
    });
  }

  private mutate(
    request: Observable<unknown>,
    message: string,
    reload: { plan?: boolean; history?: boolean },
  ): void {
    if (this._busy()) return;
    this._busy.set(true);
    request.subscribe({
      next: () => {
        this._busy.set(false);
        this.notifications.success(message);
        this.backlog.reload();
        if (reload.plan) this.plan.reload();
        if (reload.history) this.history.reload();
      },
      error: (err: unknown) => {
        this._busy.set(false);
        this.notifications.error(mutationErrorMessage(err));
      },
    });
  }
}
