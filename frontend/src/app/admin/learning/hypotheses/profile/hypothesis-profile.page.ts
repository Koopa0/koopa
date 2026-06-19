import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import {
  HypothesisService,
  type AddEvidenceRequest,
  type HypothesisLineage,
} from '../../../../core/services/hypothesis.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  Hypothesis,
  HypothesisState,
} from '../../../../core/models/workbench.model';

const STATE_DOT_CLASS: Record<HypothesisState, string> = {
  draft: 'bg-info',
  unverified: 'bg-warn',
  verified: 'bg-success',
  invalidated: 'bg-error',
  archived: 'bg-fg-faint',
};

const STATE_TEXT_CLASS: Record<HypothesisState, string> = {
  draft: 'text-info',
  unverified: 'text-warn',
  verified: 'text-success',
  invalidated: 'text-error',
  archived: 'text-fg-subtle',
};

type EvidenceKind = 'supporting' | 'counter';

/**
 * Hypothesis Profile — answers "why this hypothesis?". Layered
 * sections: Hero → Overview → Origin → Evidence → Linked observations
 * → System.
 *
 * Origin / Evidence / Observations come from
 * `/api/admin/learning/hypotheses/:id/lineage`. The page degrades
 * gracefully: on an unexpected 404/405/501 the Hero + Overview stay
 * live so the admin action bar still works, with a "couldn't load"
 * card in place of the lineage sections.
 */
@Component({
  selector: 'app-hypothesis-profile-page',
  imports: [DatePipe],
  templateUrl: './hypothesis-profile.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class HypothesisProfilePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly hypothesisService = inject(HypothesisService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly hypothesisResource = rxResource<Hypothesis, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.hypothesisService.get(params),
  });

  protected readonly lineageResource = rxResource<HypothesisLineage, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.hypothesisService.lineage(params),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives the
  // error UI; without this guard a failed fetch throws here (and in the
  // topbar effect below that reads this) and the error UI is dead.
  protected readonly hypothesis = computed(() =>
    this.hypothesisResource.hasValue()
      ? this.hypothesisResource.value()
      : undefined,
  );
  protected readonly lineage = computed(() => this.lineageResource.value());

  protected readonly isLoading = computed(
    () => this.hypothesisResource.status() === 'loading' && !this.hypothesis(),
  );
  protected readonly hasError = computed(
    () => this.hypothesisResource.status() === 'error',
  );
  /**
   * True only when the lineage endpoint returns an unexpected
   * 404/405/501. Transient 5xx / network errors fall through to the
   * regular error path so the two failure modes stay distinct.
   */
  protected readonly lineageUnavailable = computed(() => {
    if (this.lineageResource.status() !== 'error') return false;
    const err = this.lineageResource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });
  protected readonly lineageTransientError = computed(() => {
    if (this.lineageResource.status() !== 'error') return false;
    return !this.lineageUnavailable();
  });

  /**
   * /admin/learning/sessions/:id is wired. The Session Timeline
   * handles the 404 state on its own, so we can navigate without
   * hiding the link.
   */
  protected readonly sessionRouteReady = true;

  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  // Two-step inline confirm for the irreversible draft delete.
  protected readonly confirmingDelete = signal(false);

  // Add-evidence form (inline within the profile).
  protected readonly evidenceKind = signal<EvidenceKind>('supporting');
  protected readonly evidenceBody = signal('');
  protected readonly isEvidenceFormOpen = signal(false);

  // A draft is inert and pending the owner's decision (MCP v3.1): the only
  // actions are Endorse (→ unverified) and Delete. Investigation actions
  // (evidence/verify/invalidate/archive) belong to endorsed hypotheses.
  protected readonly isDraft = computed(() => this.hypothesis()?.state === 'draft');
  protected readonly canEndorse = this.isDraft;
  protected readonly canDelete = this.isDraft;
  protected readonly canAddEvidence = computed(() => {
    const h = this.hypothesis();
    return !!h && h.state !== 'draft';
  });

  // Lifecycle: hypothesis transitions from
  // unverified → {verified | invalidated | archived}. Verify and
  // Invalidate share the same gate intentionally.
  protected readonly canVerify = computed(() => {
    const h = this.hypothesis();
    return !!h && h.state === 'unverified';
  });
  protected readonly canInvalidate = this.canVerify;
  // Any non-archived, non-draft state can archive.
  protected readonly canArchive = computed(() => {
    const h = this.hypothesis();
    return !!h && h.state !== 'archived' && h.state !== 'draft';
  });

  constructor() {
    this.topbar.set({
      title: 'Hypothesis',
      crumbs: ['Learning', 'Hypotheses'],
    });

    effect(() => {
      const h = this.hypothesis();
      if (!h) return;
      this.topbar.set({
        title: `Hypothesis · ${truncate(h.claim, 40)}`,
        crumbs: ['Learning', 'Hypotheses', h.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected stateDotClass(state: HypothesisState): string {
    return STATE_DOT_CLASS[state];
  }

  protected stateTextClass(state: HypothesisState): string {
    return STATE_TEXT_CLASS[state];
  }

  protected back(): void {
    this.router.navigate(['/admin/learning/hypotheses']);
  }

  protected openSession(): void {
    const sid = this.lineage()?.origin?.session?.id;
    if (!sid) return;
    this.router.navigate(['/admin/learning/sessions', sid]);
  }

  protected toggleEvidenceForm(): void {
    this.isEvidenceFormOpen.update((v) => !v);
  }

  protected setEvidenceKind(kind: EvidenceKind): void {
    this.evidenceKind.set(kind);
  }

  protected readTextarea(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }

  protected submitEvidence(): void {
    const h = this.hypothesis();
    const body = this.evidenceBody().trim();
    if (!h || !body || this._isActioning()) return;

    const payload: AddEvidenceRequest = {
      type: this.evidenceKind(),
      body,
    };

    this._isActioning.set(true);
    this.hypothesisService.addEvidence(h.id, payload).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.evidenceBody.set('');
        this.isEvidenceFormOpen.set(false);
        this.notifications.success('Evidence recorded.');
        this.hypothesisResource.reload();
        this.lineageResource.reload();
      },
      error: () => {
        this._isActioning.set(false);
        this.notifications.error('Failed to record evidence.');
      },
    });
  }

  protected verify(): void {
    this.runTransition('verify', 'Verified');
  }

  protected invalidate(): void {
    this.runTransition('invalidate', 'Invalidated');
  }

  protected archive(): void {
    this.runTransition('archive', 'Archived');
  }

  /** Endorse a draft (draft → unverified) — the owner's decision-stamp. */
  protected endorse(): void {
    const h = this.hypothesis();
    if (!h || this._isActioning()) return;

    this._isActioning.set(true);
    this.hypothesisService.endorse(h.id).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.notifications.success('Endorsed — now unverified.');
        this.hypothesisResource.reload();
        this.lineageResource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        this.notifications.error(
          status === 409
            ? 'Already endorsed.'
            : 'Failed to endorse hypothesis.',
        );
      },
    });
  }

  protected requestDelete(): void {
    this.confirmingDelete.set(true);
  }

  protected cancelDelete(): void {
    this.confirmingDelete.set(false);
  }

  /** Delete a draft (draft-only). The row is gone, so route back to the list. */
  protected confirmDelete(): void {
    const h = this.hypothesis();
    if (!h || this._isActioning()) return;

    this._isActioning.set(true);
    this.hypothesisService.deleteDraft(h.id).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.confirmingDelete.set(false);
        this.notifications.success('Draft deleted.');
        this.router.navigate(['/admin/learning/hypotheses']);
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        this.confirmingDelete.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        this.notifications.error(
          status === 409
            ? 'Only drafts can be deleted.'
            : 'Failed to delete draft.',
        );
      },
    });
  }

  private runTransition(
    action: 'verify' | 'invalidate' | 'archive',
    label: string,
  ): void {
    const h = this.hypothesis();
    if (!h || this._isActioning()) return;

    const call =
      action === 'verify'
        ? this.hypothesisService.verify(h.id)
        : action === 'invalidate'
          ? this.hypothesisService.invalidate(h.id)
          : this.hypothesisService.archive(h.id);

    this._isActioning.set(true);
    call.subscribe({
      next: () => {
        this._isActioning.set(false);
        this.notifications.success(`${label} hypothesis.`);
        this.hypothesisResource.reload();
        this.lineageResource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        if (status === 400) {
          this.notifications.error('Illegal state transition.');
        } else {
          this.notifications.error(`Failed to ${action} hypothesis.`);
        }
      },
    });
  }
}

function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}
