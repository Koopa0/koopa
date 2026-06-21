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
  type ProposedProject,
} from '../../../core/services/proposal.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { ModalComponent } from '../../../shared/components/modal/modal.component';

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

/** A standalone proposed project. */
interface ProjectCard {
  kind: 'project';
  key: string;
  project: ProposedProject;
}

type TriageCard = AreaCard | GoalCard | ProjectCard;

/** A pending reject awaiting the owner's confirmation in the dialog. `action`
 *  runs the actual hard-delete once confirmed — the service is never touched
 *  until then, so dismissing the dialog leaves the proposal untouched. */
interface PendingReject {
  title: string;
  body: string;
  confirmLabel: string;
  action: () => void;
}

/** Wraps a proposed goal as a standalone review card. */
function goalCard(goal: ProposedGoal): GoalCard {
  return { kind: 'goal', key: `goal:${goal.id}`, goal };
}

/** Splits a proposals payload into review cards: each proposed area becomes a
 *  bundle card carrying its proposed child goals; every goal not under a
 *  proposed area is a standalone card; every proposed project is a standalone
 *  card. The template groups them back into Areas → Goals → Projects sections;
 *  each group is already newest-first from the backend. */
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
    .map(goalCard);
  const projectCards: ProjectCard[] = resp.projects.map((project) => ({
    kind: 'project',
    key: `project:${project.id}`,
    project,
  }));
  return [...areaCards, ...goalCards, ...projectCards];
}

/**
 * Proposals triage — the owner reviews every agent-proposed inert
 * goal/area/project draft at once, grouped Areas → Goals → Projects (PARA
 * order). Accept promotes a draft into the live planning lifecycle and drops
 * its row; reject opens a confirm dialog, then hard-deletes it (an area reject
 * cascades its proposed child goals server-side). Resolutions splice the row
 * out of the working list locally — no reload flash. Accepting an area is the
 * exception: it touches only the area, so its still-proposed child goals
 * resurface as standalone goal rows for individual review rather than vanishing
 * with the bundle. The nav badge re-reads its own count on the next
 * navigation, so the page stays decoupled from it while triaging in place.
 */
@Component({
  selector: 'app-proposals-triage-page',
  templateUrl: './proposals-triage.page.html',
  imports: [ModalComponent],
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

  // Working list: seeded from the loaded cards, spliced locally as the owner
  // resolves each one. linkedSignal re-seeds only on (re)load — never on a
  // local splice — so a resolved row stays gone without a refetch.
  protected readonly cards = linkedSignal(() => this.builtCards());

  // The template renders one section per kind; each reads its slice off the
  // working list, so a local splice updates exactly the right group.
  protected readonly areaCards = computed(() =>
    this.cards().filter((c): c is AreaCard => c.kind === 'area'),
  );
  protected readonly goalCards = computed(() =>
    this.cards().filter((c): c is GoalCard => c.kind === 'goal'),
  );
  protected readonly projectCards = computed(() =>
    this.cards().filter((c): c is ProjectCard => c.kind === 'project'),
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.resource.hasValue(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  // Empty once nothing is left to review — covers both "none was ever proposed"
  // and "the owner cleared the list".
  protected readonly isEmpty = computed(
    () => !this.isLoading() && !this.hasError() && this.cards().length === 0,
  );

  /** True while an action is in flight — gates every row's buttons. */
  protected readonly busy = signal(false);

  /** Set when a reject is awaiting confirmation; drives the confirm dialog.
   *  Null means no dialog is open. */
  protected readonly pendingReject = signal<PendingReject | null>(null);

  constructor() {
    this.topbar.set({ title: 'Proposals', crumbs: ['Commitment', 'Proposals'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  // ── Accept ─────────────────────────────────────────────────────

  /** Activate the area only. Its proposed child goals stay proposed under the
   *  now-active area, so they resurface locally as standalone goal rows. */
  protected acceptArea(card: AreaCard): void {
    this.run(
      this.proposalService.activateArea(card.area.id),
      `Activated "${card.area.name}"`,
      () => this.resurfaceAreaGoals(card),
    );
  }

  protected acceptGoal(card: GoalCard): void {
    this.run(
      this.proposalService.activateGoal(card.goal.id),
      `Activated "${card.goal.title}"`,
      () => this.removeCard(card.key),
    );
  }

  protected acceptProject(card: ProjectCard): void {
    this.run(
      this.proposalService.activateProject(card.project.id),
      `Activated "${card.project.title}"`,
      () => this.removeCard(card.key),
    );
  }

  // ── Reject (deferred behind the confirm dialog) ────────────────

  protected rejectArea(card: AreaCard): void {
    if (this.busy()) return;
    const n = card.goals.length;
    const body =
      n === 0
        ? 'This permanently removes the proposed area.'
        : n === 1
          ? 'This also rejects 1 proposed goal under it.'
          : `This also rejects ${n} proposed goals under it.`;
    this.pendingReject.set({
      title: `Reject "${card.area.name}"?`,
      body,
      confirmLabel: 'Reject bundle',
      action: () =>
        this.run(
          this.proposalService.rejectArea(card.area.id),
          'Proposal bundle rejected',
          () => this.removeCard(card.key),
        ),
    });
  }

  protected rejectGoal(card: GoalCard): void {
    if (this.busy()) return;
    this.pendingReject.set({
      title: `Reject "${card.goal.title}"?`,
      body: 'This permanently removes the proposed goal.',
      confirmLabel: 'Reject goal',
      action: () =>
        this.run(
          this.proposalService.rejectGoal(card.goal.id),
          'Proposal rejected',
          () => this.removeCard(card.key),
        ),
    });
  }

  protected rejectProject(card: ProjectCard): void {
    if (this.busy()) return;
    this.pendingReject.set({
      title: `Reject "${card.project.title}"?`,
      body: 'This permanently removes the proposed project.',
      confirmLabel: 'Reject project',
      action: () =>
        this.run(
          this.proposalService.rejectProject(card.project.id),
          'Proposal rejected',
          () => this.removeCard(card.key),
        ),
    });
  }

  // ── Reject confirmation dialog ─────────────────────────────────

  /** Runs the pending reject's action and closes the dialog. The action runs
   *  the real hard-delete (deferred until now), then `run` settles the list. */
  protected confirmReject(): void {
    const pending = this.pendingReject();
    if (!pending || this.busy()) return;
    this.pendingReject.set(null);
    pending.action();
  }

  /** Dismisses the dialog without touching the proposal. */
  protected cancelReject(): void {
    this.pendingReject.set(null);
  }

  // ── Shared action runner ───────────────────────────────────────

  /** Runs a triage mutation, then applies `resolve` (the local list edit) and
   *  shows a toast. On failure the row stays put so the owner can retry. */
  private run(op: Observable<void>, success: string, resolve: () => void): void {
    if (this.busy()) return;
    this.busy.set(true);
    op.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        resolve();
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

  /** Drops a resolved row from the working list. */
  private removeCard(key: string): void {
    this.cards.update((list) => list.filter((c) => c.key !== key));
  }

  /** Replaces an accepted area bundle with standalone goal rows for its
   *  still-proposed children, so they don't vanish before review — the local
   *  equivalent of what a refetch would surface now the area is active. */
  private resurfaceAreaGoals(card: AreaCard): void {
    this.cards.update((list) => [
      ...list.filter((c) => c.key !== card.key),
      ...card.goals.map(goalCard),
    ]);
  }
}
