import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  linkedSignal,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import {
  ProposalService,
  type ProposalsResponse,
  type ProposedArea,
  type ProposedGoal,
} from '../../../core/services/proposal.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

/** A proposed area plus its proposed child goals — reviewed as one bundle. */
interface AreaCard {
  kind: 'area';
  key: string;
  area: ProposedArea;
  goals: ProposedGoal[];
}

/** A standalone proposed goal (no proposed-area parent). */
interface GoalCard {
  kind: 'goal';
  key: string;
  goal: ProposedGoal;
}

type TriageCard = AreaCard | GoalCard;

/** Splits a proposals payload into review cards: each proposed area becomes a
 *  bundle card carrying its proposed child goals; every goal not under a
 *  proposed area is a standalone card. Areas (bundles) lead, then standalone
 *  goals — both already newest-first from the backend. */
function buildCards(resp: ProposalsResponse): TriageCard[] {
  const proposedAreaIds = new Set(resp.areas.map((a) => a.id));
  const areaCards: AreaCard[] = resp.areas.map((area) => ({
    kind: 'area',
    key: `area:${area.id}`,
    area,
    goals: resp.goals.filter((g) => g.area_id === area.id),
  }));
  const goalCards: GoalCard[] = resp.goals
    .filter((g) => !g.area_id || !proposedAreaIds.has(g.area_id))
    .map((goal) => ({ kind: 'goal', key: `goal:${goal.id}`, goal }));
  return [...areaCards, ...goalCards];
}

/**
 * Proposals triage — the owner's one-card-at-a-time review of agent-proposed
 * inert goal/area drafts. Each card is either a proposed area bundle (area +
 * its proposed goals, accepted or rejected as a unit) or a standalone proposed
 * goal. Activate promotes a draft into the live planning lifecycle; reject
 * hard-deletes it (an area reject cascades its goals server-side). Cards are
 * spliced off the head locally as they're resolved — no reload flash — and the
 * nav badge is refreshed after each action so the count tracks the queue.
 */
@Component({
  selector: 'app-proposals-triage-page',
  templateUrl: './proposals-triage.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ProposalsTriagePageComponent {
  private readonly proposalService = inject(ProposalService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<ProposalsResponse, void>({
    stream: () => this.proposalService.list(),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom).
  private readonly builtCards = computed<TriageCard[]>(() =>
    this.resource.hasValue() ? buildCards(this.resource.value()) : [],
  );

  // Working queue: seeded from the loaded cards, spliced locally as the owner
  // resolves each one. linkedSignal re-seeds only on (re)load — never on a
  // local splice — so a resolved card stays gone without a refetch.
  protected readonly cards = linkedSignal(() => this.builtCards());

  protected readonly current = computed<TriageCard | undefined>(
    () => this.cards()[0],
  );
  protected readonly currentArea = computed(() => {
    const c = this.current();
    return c && c.kind === 'area' ? c : undefined;
  });
  protected readonly currentGoal = computed(() => {
    const c = this.current();
    return c && c.kind === 'goal' ? c : undefined;
  });

  /** Total cards at load (stable — the queue is never reloaded mid-review). */
  protected readonly total = computed(() => this.builtCards().length);
  protected readonly remaining = computed(() => this.cards().length);
  /** 1-based position of the current card in the original queue. */
  protected readonly position = computed(
    () => this.total() - this.remaining() + 1,
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.resource.hasValue(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && !this.hasError() && this.total() === 0,
  );
  protected readonly allClear = computed(
    () =>
      !this.isLoading() &&
      !this.hasError() &&
      this.total() > 0 &&
      this.remaining() === 0,
  );

  /** True while an action is in flight — gates the card's buttons. */
  protected readonly busy = signal(false);

  // Inline edit-then-activate for a standalone goal.
  protected readonly editing = signal(false);
  protected readonly editTitle = signal('');
  protected readonly canSaveEdit = computed(
    () => this.editTitle().trim().length > 0 && !this.busy(),
  );

  constructor() {
    this.topbar.set({ title: 'Proposals', crumbs: ['Commitment', 'Proposals'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected readValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  // ── Goal card ──────────────────────────────────────────────────

  protected startEdit(): void {
    const card = this.currentGoal();
    if (!card) return;
    this.editTitle.set(card.goal.title);
    this.editing.set(true);
  }

  protected cancelEdit(): void {
    this.editing.set(false);
  }

  /** Activate the current standalone goal. In edit mode, persist the new
   *  title first when it changed, then activate. */
  protected activateGoal(): void {
    const card = this.currentGoal();
    if (!card) return;
    const edited = this.editTitle().trim();
    if (this.editing()) {
      if (!edited) return;
      const op =
        edited === card.goal.title
          ? this.proposalService.activateGoal(card.goal.id)
          : this.proposalService.editThenActivateGoal(card.goal.id, edited);
      this.run(op, `Activated "${edited}"`);
    } else {
      this.run(
        this.proposalService.activateGoal(card.goal.id),
        `Activated "${card.goal.title}"`,
      );
    }
  }

  protected rejectGoal(): void {
    const card = this.currentGoal();
    if (!card || this.busy()) return;
    if (
      !window.confirm(
        `Reject "${card.goal.title}"? This permanently removes the proposed goal.`,
      )
    ) {
      return;
    }
    this.run(this.proposalService.rejectGoal(card.goal.id), 'Proposal rejected');
  }

  // ── Area bundle card ───────────────────────────────────────────

  protected activateArea(): void {
    const card = this.currentArea();
    if (!card) return;
    this.run(
      this.proposalService.activateBundle(
        card.area.id,
        card.goals.map((g) => g.id),
      ),
      `Activated "${card.area.name}"`,
    );
  }

  protected rejectArea(): void {
    const card = this.currentArea();
    if (!card || this.busy()) return;
    const n = card.goals.length;
    const message =
      n === 0
        ? `Reject "${card.area.name}"?`
        : n === 1
          ? `Reject "${card.area.name}"? This also rejects 1 proposed goal under it.`
          : `Reject "${card.area.name}"? This also rejects ${n} proposed goals under it.`;
    if (!window.confirm(message)) return;
    this.run(
      this.proposalService.rejectArea(card.area.id),
      'Proposal bundle rejected',
    );
  }

  // ── Shared action runner ───────────────────────────────────────

  /** Runs a triage mutation, then advances to the next card and refreshes the
   *  nav badge. On failure the card stays put so the owner can retry. */
  private run(op: Observable<void>, success: string): void {
    if (this.busy()) return;
    this.busy.set(true);
    op.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        this.advance();
        this.notifications.success(success);
      },
      error: () => {
        this.busy.set(false);
        this.notifications.error(
          "Couldn't apply that. The proposal is still here — try again.",
        );
      },
    });
  }

  /** Drops the resolved head card and resets per-card edit state. The nav
   *  badge re-reads its count on the next NavigationEnd (AdminLayout), so the
   *  page stays decoupled from the nav-count service while triaging in place. */
  private advance(): void {
    this.editing.set(false);
    this.cards.update((list) => list.slice(1));
  }
}
