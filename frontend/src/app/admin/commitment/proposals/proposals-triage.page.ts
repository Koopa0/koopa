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

/** Splits a proposals payload into review cards: each proposed area becomes a
 *  bundle card carrying its proposed child goals; every goal not under a
 *  proposed area is a standalone card; every proposed project is a standalone
 *  card. Areas (bundles) lead, then standalone goals, then projects — each
 *  group already newest-first from the backend. */
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
  const projectCards: ProjectCard[] = resp.projects.map((project) => ({
    kind: 'project',
    key: `project:${project.id}`,
    project,
  }));
  return [...areaCards, ...goalCards, ...projectCards];
}

/**
 * Proposals triage — the owner's one-card-at-a-time review of agent-proposed
 * inert goal/area/project drafts. Each card is a proposed area (reviewed on its
 * own), a standalone proposed goal, or a proposed project. Activate promotes a
 * draft into the live planning lifecycle; reject hard-deletes it (an area reject
 * cascades its proposed goals server-side). Most resolutions splice the head
 * card off the queue locally — no reload flash. Activating an area is the
 * exception: it touches only the area, so its still-proposed child goals are
 * re-fetched and resurface as standalone cards for individual review. The nav
 * badge re-reads its count after each action so it tracks the queue.
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
  protected readonly currentProject = computed(() => {
    const c = this.current();
    return c && c.kind === 'project' ? c : undefined;
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

  /** Set when a reject is awaiting confirmation; drives the confirm dialog.
   *  Null means no dialog is open. */
  protected readonly pendingReject = signal<PendingReject | null>(null);

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
    this.pendingReject.set({
      title: `Reject "${card.goal.title}"?`,
      body: 'This permanently removes the proposed goal.',
      confirmLabel: 'Reject goal',
      action: () =>
        this.run(
          this.proposalService.rejectGoal(card.goal.id),
          'Proposal rejected',
        ),
    });
  }

  // ── Area bundle card ───────────────────────────────────────────

  /** Activate the current area only. Its proposed child goals stay proposed
   *  under the now-active area, so the queue re-fetches and they resurface as
   *  standalone cards for individual review. */
  protected activateArea(): void {
    const card = this.currentArea();
    if (!card) return;
    this.run(
      this.proposalService.activateArea(card.area.id),
      `Activated "${card.area.name}"`,
      { reload: true },
    );
  }

  protected rejectArea(): void {
    const card = this.currentArea();
    if (!card || this.busy()) return;
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
        ),
    });
  }

  // ── Project card ───────────────────────────────────────────────

  /** Activate the current proposed project (proposed → in_progress). */
  protected activateProject(): void {
    const card = this.currentProject();
    if (!card) return;
    this.run(
      this.proposalService.activateProject(card.project.id),
      `Activated "${card.project.title}"`,
    );
  }

  protected rejectProject(): void {
    const card = this.currentProject();
    if (!card || this.busy()) return;
    this.pendingReject.set({
      title: `Reject "${card.project.title}"?`,
      body: 'This permanently removes the proposed project.',
      confirmLabel: 'Reject project',
      action: () =>
        this.run(
          this.proposalService.rejectProject(card.project.id),
          'Proposal rejected',
        ),
    });
  }

  // ── Reject confirmation dialog ─────────────────────────────────

  /** Runs the pending reject's action and closes the dialog. The action runs
   *  the real hard-delete (deferred until now), then `run` settles the queue. */
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

  /** Runs a triage mutation, then settles the queue and shows a toast. By
   *  default the resolved head card is spliced off locally; pass `reload` to
   *  re-fetch instead — used by area activate so still-proposed children
   *  resurface. On failure the card stays put so the owner can retry. */
  private run(
    op: Observable<void>,
    success: string,
    opts: { reload?: boolean } = {},
  ): void {
    if (this.busy()) return;
    this.busy.set(true);
    op.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        if (opts.reload) {
          this.editing.set(false);
          this.resource.reload();
        } else {
          this.advance();
        }
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
