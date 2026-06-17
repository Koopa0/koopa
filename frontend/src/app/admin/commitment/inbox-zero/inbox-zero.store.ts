import { Injectable, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { of, switchMap, type Observable } from 'rxjs';
import {
  TodoService,
  type TodoItem,
  type TodoRow,
} from '../../../core/services/todo.service';
import {
  DailyPlanService,
  type DailyPlan,
} from '../../../core/services/daily-plan.service';
import { NotificationService } from '../../../core/services/notification.service';
import {
  appendToPlan,
  clarifyUpdate,
  mutationErrorMessage,
  planMemberIds,
  type ClarifyResult,
} from '../todos/gtd-view';

const BACKLOG_PAGE_SIZE = 200;

/**
 * Why a clarify dialog was opened. `clarify` lands the capture as a plain
 * todo; `pull` additionally appends it to today's plan after the
 * inbox→todo transition (the daily-plan PUT rejects inbox-state todos, so
 * a capture can never be pulled into today without clarifying first).
 */
export type ClarifyIntent = 'clarify' | 'pull';

export interface ClarifyRequest {
  row: TodoRow;
  intent: ClarifyIntent;
}

/**
 * Page-scoped state for Inbox Zero triage: the inbox queue + today's plan
 * resources, the current card cursor, the active clarify request, and the
 * per-card decision round-trips (clarify, clarify-and-pull, defer, drop).
 *
 * Unlike the GTD store this is single-stream and one-card-at-a-time:
 * decisions advance the cursor optimistically and roll it back on error,
 * so the operator sees the next card immediately and only the failed card
 * reappears. Provided by the page so the state dies with the route.
 */
@Injectable()
export class InboxZeroStore {
  private readonly todoService = inject(TodoService);
  private readonly dailyPlanService = inject(DailyPlanService);
  private readonly notifications = inject(NotificationService);

  // Cursor into the resolved queue. Decisions optimistically advance the
  // backing data (the resource reloads with the row gone), so the cursor
  // mostly stays put while the queue shrinks under it.
  readonly cursor = signal(0);
  readonly clarifyRequest = signal<ClarifyRequest | null>(null);
  private readonly _busy = signal(false);
  readonly busy = this._busy.asReadonly();

  readonly inbox = rxResource<TodoRow[], void>({
    stream: () =>
      this.todoService.list({ state: 'inbox', per_page: BACKLOG_PAGE_SIZE }),
  });
  readonly plan = rxResource<DailyPlan, void>({
    stream: () => this.dailyPlanService.today(),
  });

  // rxResource.value() throws while the resource is in the error state, so
  // reads go through this hasValue()-guarded view.
  readonly queue = computed<TodoRow[]>(() =>
    this.inbox.hasValue() ? this.inbox.value() : [],
  );
  readonly total = computed(() => this.queue().length);
  readonly position = computed(() =>
    Math.min(this.cursor(), Math.max(this.total() - 1, 0)),
  );
  readonly current = computed<TodoRow | null>(
    () => this.queue()[this.position()] ?? null,
  );
  // 1-based ordinal of the active card for the "N / M left" counter.
  readonly ordinal = computed(() =>
    this.total() === 0 ? 0 : this.position() + 1,
  );

  readonly loading = computed(() => this.inbox.status() === 'loading');
  readonly errored = computed(() => this.inbox.status() === 'error');
  // Cleared only once the queue has actually loaded — an empty array before
  // the first response must not flash the done state.
  readonly done = computed(
    () => this.inbox.status() === 'resolved' && this.total() === 0,
  );

  private readonly planIds = computed(() =>
    planMemberIds(this.plan.hasValue() ? this.plan.value().items : []),
  );

  reload(): void {
    this.inbox.reload();
  }

  /** Open the clarify dialog for the current card. */
  openClarify(intent: ClarifyIntent): void {
    const row = this.current();
    if (!row || this._busy()) return;
    this.clarifyRequest.set({ row, intent });
  }

  closeClarify(): void {
    this.clarifyRequest.set(null);
  }

  /**
   * Clarify-dialog submit. Applies the optional field update, advances the
   * capture inbox→todo, and — when the dialog was opened with `pull` —
   * appends the new todo to today's plan. Advances to the next card.
   */
  clarified(result: ClarifyResult): void {
    const request = this.clarifyRequest();
    if (!request) return;
    this.clarifyRequest.set(null);
    const { row, intent } = request;
    const fields = clarifyUpdate(result);
    const update$: Observable<TodoItem | null> = fields
      ? this.todoService.update(row.id, fields)
      : of(null);
    const chain$ = update$.pipe(
      switchMap(() => this.todoService.advance(row.id, 'clarify')),
    );
    if (intent === 'pull') {
      this.runPullChain(row, chain$);
    } else {
      this.decide(chain$, 'Clarified → todo', { plan: false });
    }
  }

  /** Defer the current card to someday. */
  defer(): void {
    const row = this.current();
    if (!row) return;
    this.decide(this.todoService.advance(row.id, 'defer'), 'Deferred → someday', {
      plan: false,
    });
  }

  /** Clarify dialog's "defer instead" escape: close, then defer. */
  deferInstead(): void {
    if (this.clarifyRequest() === null) return;
    this.clarifyRequest.set(null);
    this.defer();
  }

  /** Drop the current card (inbox-only hard delete). */
  drop(): void {
    const row = this.current();
    if (!row) return;
    this.decide(this.todoService.advance(row.id, 'drop'), 'Dropped', {
      plan: false,
    });
  }

  // Append the freshly-clarified todo to today's plan, then settle the
  // card. The plan must be loaded; a stale/missing plan aborts before the
  // clarify fires so nothing half-applies.
  private runPullChain(
    row: TodoRow,
    clarify$: Observable<TodoItem | null>,
  ): void {
    if (!this.plan.hasValue()) {
      this.notifications.error('Today’s plan has not loaded yet.');
      return;
    }
    const plan = this.plan.value();
    if (this.planIds().has(row.id)) {
      this.decide(clarify$, 'Clarified → todo', { plan: false });
      return;
    }
    const pull$ = clarify$.pipe(
      switchMap(() =>
        this.dailyPlanService.replace(appendToPlan(plan.items, row.id)),
      ),
    );
    this.decide(pull$, 'Pulled into today', { plan: true });
  }

  // Run one card decision: lock input, advance the cursor optimistically,
  // and reload the queue on success. On error roll the cursor back so the
  // failed card returns to view, and surface the message.
  private decide(
    request: Observable<unknown>,
    message: string,
    reload: { plan: boolean },
  ): void {
    if (this._busy()) return;
    this._busy.set(true);
    const restoreAt = this.position();
    request.subscribe({
      next: () => {
        this._busy.set(false);
        this.notifications.success(message);
        this.inbox.reload();
        if (reload.plan) this.plan.reload();
      },
      error: (err: unknown) => {
        this._busy.set(false);
        this.cursor.set(restoreAt);
        this.notifications.error(mutationErrorMessage(err));
      },
    });
  }
}
