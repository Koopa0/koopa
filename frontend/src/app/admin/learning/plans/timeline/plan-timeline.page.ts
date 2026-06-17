import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  linkedSignal,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  CdkDrag,
  CdkDragHandle,
  CdkDropList,
  moveItemInArray,
} from '@angular/cdk/drag-drop';
import type { CdkDragDrop } from '@angular/cdk/drag-drop';
import { map, of } from 'rxjs';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { ModalComponent } from '../../../../shared/components/modal/modal.component';
import { StatusBadgeComponent } from '../../../../shared/components/status-badge/status-badge.component';
import type { BadgeVariant } from '../../../../shared/components/status-badge/status-badge.component';
import type {
  PlanDetail,
  PlanEntryDetail,
  PlanEntryStatus,
  PlanProgress,
  PlanStatus,
  TargetAttempt,
} from '../../../../core/models/learning.model';

/**
 * Full-plan reorder payload: every entry, positions rewritten 0..n-1 in
 * array order. The reorder endpoint rejects requests whose positions
 * collide with untouched entries, so always sending the complete set keeps
 * the request conflict-free by construction.
 */
export function reorderPayload(
  entries: readonly PlanEntryDetail[],
): { plan_entry_id: string; position: number }[] {
  return entries.map((e, i) => ({ plan_entry_id: e.plan_entry_id, position: i }));
}

const ENTRY_STATUS_VARIANT: Record<PlanEntryStatus, BadgeVariant> = {
  planned: 'neutral',
  completed: 'success',
  skipped: 'neutral',
  substituted: 'info',
};

const PLAN_STATUS_VARIANT: Record<PlanStatus, BadgeVariant> = {
  draft: 'neutral',
  active: 'info',
  paused: 'warning',
  completed: 'success',
  abandoned: 'neutral',
};

/** Prototype phase vocabulary → badge variants; unknown phases stay neutral. */
const PHASE_VARIANT: Record<string, BadgeVariant> = {
  foundation: 'neutral',
  core: 'info',
  applied: 'info',
  mastery: 'success',
};

interface StatusAction {
  label: string;
  to: PlanStatus;
  kind: 'primary' | 'ghost' | 'danger';
}

/** Lifecycle controls per current plan status; terminal states get none. */
const STATUS_ACTIONS: Record<PlanStatus, StatusAction[]> = {
  draft: [{ label: 'Activate', to: 'active', kind: 'primary' }],
  active: [
    { label: 'Pause', to: 'paused', kind: 'ghost' },
    { label: 'Complete', to: 'completed', kind: 'ghost' },
    { label: 'Abandon', to: 'abandoned', kind: 'danger' },
  ],
  paused: [
    { label: 'Resume', to: 'active', kind: 'primary' },
    { label: 'Complete', to: 'completed', kind: 'ghost' },
    { label: 'Abandon', to: 'abandoned', kind: 'danger' },
  ],
  completed: [],
  abandoned: [],
};

/**
 * Plan detail — the design's PlanDetail screen reworked over the real
 * `{ plan, entries, progress }` envelope.
 *
 * - Entries render in position order with phase + status badges and
 *   drag-to-reorder (CDK DragDrop). A drop optimistically reorders the
 *   local list, persists through the reorder endpoint, and re-renders
 *   from the returned envelope (rolled back on error).
 * - Plan lifecycle (draft→active activation, pause / complete / abandon)
 *   goes through the status endpoint.
 * - Completing an entry is audit-gated per mcp-decision-policy §13: the
 *   modal requires the justifying attempt + a reason; the server rejects
 *   anything less with 400 AUDIT_REQUIRED. The justifying attempt is picked
 *   from the entry target's attempts (GET targets/{id}/attempts), each
 *   option showing its outcome + date so the attempt is recognizable.
 * - Skip is a plain transition; substitution requires picking the
 *   substituting entry (`substituted_by` references a sibling entry).
 * - Entry removal is draft-only (the server 409s otherwise), so the
 *   affordance is hidden for any other plan status.
 */
@Component({
  selector: 'app-plan-timeline-page',
  standalone: true,
  imports: [
    DatePipe,
    CdkDropList,
    CdkDrag,
    CdkDragHandle,
    ModalComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './plan-timeline.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class PlanTimelinePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<PlanDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.learningService.plan(params),
  });

  protected readonly detail = computed(() => this.resource.value());
  protected readonly plan = computed(() => this.detail()?.plan);
  protected readonly progress = computed(() => this.detail()?.progress);
  /** Linked goal's title for the meta strip; "" when the plan has no goal. */
  protected readonly goalName = computed(() => this.detail()?.goal_name ?? '');

  /**
   * Local working copy of the entries — the drag preview reorders this
   * before the server confirms; any envelope refresh resets it.
   */
  protected readonly entries = linkedSignal(
    () => this.detail()?.entries ?? [],
  );

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.detail(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /** One mutation at a time — drag and all actions disable while in flight. */
  protected readonly busy = signal(false);
  protected readonly actionError = signal<string | null>(null);

  protected readonly statusActions = computed<StatusAction[]>(() => {
    const p = this.plan();
    return p ? STATUS_ACTIONS[p.status] : [];
  });

  protected readonly isDraft = computed(
    () => this.plan()?.status === 'draft',
  );

  protected readonly completedPct = computed(() =>
    this.segmentPct((p) => p.completed),
  );
  protected readonly substitutedPct = computed(() =>
    this.segmentPct((p) => p.substituted),
  );
  protected readonly skippedPct = computed(() =>
    this.segmentPct((p) => p.skipped),
  );

  // --- Audit-gate modal (complete) ---
  protected readonly completeTarget = signal<PlanEntryDetail | null>(null);
  protected readonly selectedAttemptId = signal<string | null>(null);
  protected readonly completeReason = signal('');
  protected readonly modalError = signal<string | null>(null);

  // The picker lists the entry target's attempts (newest first). It keys off
  // the open complete-target's learning_target_id; closing the modal stops the
  // read by resolving the key to ''.
  private readonly attemptsResource = rxResource<TargetAttempt[], string>({
    params: () => this.completeTarget()?.learning_target_id ?? '',
    stream: ({ params }) =>
      params
        ? this.learningService.targetAttempts(params)
        : of<TargetAttempt[]>([]),
  });
  protected readonly attempts = computed<TargetAttempt[]>(() =>
    this.attemptsResource.hasValue() ? this.attemptsResource.value() : [],
  );
  protected readonly attemptsLoading = computed(
    () => this.attemptsResource.status() === 'loading',
  );
  protected readonly attemptsError = computed(
    () => this.attemptsResource.status() === 'error',
  );

  protected readonly completeReady = computed(
    () =>
      this.selectedAttemptId() !== null &&
      this.completeReason().trim().length > 0,
  );

  // --- Substitute modal ---
  protected readonly substituteTarget = signal<PlanEntryDetail | null>(null);
  protected readonly substitutePick = signal<string | null>(null);

  /** Candidate substitutes: every other entry of the plan. */
  protected readonly substituteOptions = computed(() => {
    const target = this.substituteTarget();
    if (!target) return [];
    return this.entries().filter(
      (e) => e.plan_entry_id !== target.plan_entry_id,
    );
  });

  constructor() {
    this.topbar.set({ title: 'Learning plan', crumbs: ['Learning', 'Plans'] });

    effect(() => {
      const p = this.plan();
      if (!p) return;
      this.topbar.set({
        title: `Plan · ${p.title}`,
        crumbs: ['Learning', 'Plans', p.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected back(): void {
    this.router.navigate(['/admin/learning/plans']);
  }

  protected entryStatusVariant(s: PlanEntryStatus): BadgeVariant {
    return ENTRY_STATUS_VARIANT[s];
  }

  protected planStatusVariant(s: PlanStatus): BadgeVariant {
    return PLAN_STATUS_VARIANT[s];
  }

  protected phaseVariant(phase: string): BadgeVariant {
    return PHASE_VARIANT[phase] ?? 'neutral';
  }

  /** Selects an attempt as the justifying attempt for completion. */
  protected pickAttempt(id: string): void {
    this.selectedAttemptId.set(id);
  }

  /** Resolves a substituted_by entry id to its target title for display. */
  protected substitutedLabel(e: PlanEntryDetail): string {
    const id = e.substituted_by;
    if (!id) return '';
    const sub = this.entries().find((x) => x.plan_entry_id === id);
    return sub ? sub.target_title : id.slice(0, 8);
  }

  // --- Lifecycle ---

  protected setPlanStatus(to: PlanStatus): void {
    if (this.busy()) return;
    const p = this.plan();
    if (!p) return;
    this.busy.set(true);
    this.actionError.set(null);
    this.learningService
      .updatePlanStatus(p.id, to)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.resource.reload();
        },
        error: () => {
          this.busy.set(false);
          this.actionError.set('Could not update the plan status.');
        },
      });
  }

  // --- Reorder ---

  protected drop(event: CdkDragDrop<PlanEntryDetail[]>): void {
    if (event.previousIndex === event.currentIndex || this.busy()) return;
    const p = this.plan();
    if (!p) return;

    const next = [...this.entries()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.entries.set(next); // optimistic preview

    this.busy.set(true);
    this.actionError.set(null);
    this.learningService
      .reorderPlanEntries(p.id, reorderPayload(next))
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (envelope) => {
          this.busy.set(false);
          // Re-render from the server's envelope, not the local guess.
          this.resource.set(envelope);
        },
        error: () => {
          this.busy.set(false);
          this.entries.set(this.detail()?.entries ?? []); // roll back
          this.actionError.set('Could not save the new order.');
        },
      });
  }

  // --- Entry removal (draft only) ---

  protected removeEntry(e: PlanEntryDetail): void {
    if (this.busy() || !this.isDraft()) return;
    const p = this.plan();
    if (!p) return;
    this.busy.set(true);
    this.actionError.set(null);
    this.learningService
      .removePlanEntry(p.id, e.plan_entry_id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.resource.reload();
        },
        error: () => {
          this.busy.set(false);
          this.actionError.set('Could not remove the entry.');
        },
      });
  }

  // --- Skip (plain transition, no extra gate) ---

  protected skipEntry(e: PlanEntryDetail): void {
    if (this.busy()) return;
    const p = this.plan();
    if (!p) return;
    this.busy.set(true);
    this.actionError.set(null);
    this.learningService
      .updatePlanEntry(p.id, e.plan_entry_id, { status: 'skipped' })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.resource.reload();
        },
        error: () => {
          this.busy.set(false);
          this.actionError.set('Could not skip the entry.');
        },
      });
  }

  // --- Audit-gated completion ---

  protected openComplete(e: PlanEntryDetail): void {
    this.completeTarget.set(e);
    this.selectedAttemptId.set(null);
    this.completeReason.set('');
    this.modalError.set(null);
  }

  protected cancelComplete(): void {
    this.completeTarget.set(null);
  }

  protected setCompleteReason(event: Event): void {
    this.completeReason.set((event.target as HTMLTextAreaElement).value);
  }

  protected confirmComplete(): void {
    const target = this.completeTarget();
    const p = this.plan();
    const attemptId = this.selectedAttemptId();
    if (!target || !p || !attemptId || !this.completeReady() || this.busy())
      return;
    this.busy.set(true);
    this.modalError.set(null);
    this.learningService
      .updatePlanEntry(p.id, target.plan_entry_id, {
        status: 'completed',
        completed_by_attempt_id: attemptId,
        reason: this.completeReason().trim(),
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.completeTarget.set(null);
          this.resource.reload();
        },
        error: () => {
          this.busy.set(false);
          this.modalError.set(
            'The server rejected the completion — check that the attempt id exists and belongs to this entry’s target.',
          );
        },
      });
  }

  // --- Substitution ---

  protected openSubstitute(e: PlanEntryDetail): void {
    this.substituteTarget.set(e);
    this.substitutePick.set(null);
    this.modalError.set(null);
  }

  protected cancelSubstitute(): void {
    this.substituteTarget.set(null);
  }

  protected confirmSubstitute(): void {
    const target = this.substituteTarget();
    const pick = this.substitutePick();
    const p = this.plan();
    if (!target || !pick || !p || this.busy()) return;
    this.busy.set(true);
    this.modalError.set(null);
    this.learningService
      .updatePlanEntry(p.id, target.plan_entry_id, {
        status: 'substituted',
        substituted_by: pick,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.substituteTarget.set(null);
          this.resource.reload();
        },
        error: () => {
          this.busy.set(false);
          this.modalError.set('Could not record the substitution.');
        },
      });
  }

  private segmentPct(pick: (p: PlanProgress) => number): number {
    const p = this.progress();
    if (!p || p.total === 0) return 0;
    return (pick(p) / p.total) * 100;
  }
}
