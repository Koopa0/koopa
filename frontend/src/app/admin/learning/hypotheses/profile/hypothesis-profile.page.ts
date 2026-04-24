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
  unverified: 'bg-amber-400',
  verified: 'bg-emerald-500',
  invalidated: 'bg-red-500',
  archived: 'bg-zinc-600',
};

const STATE_TEXT_CLASS: Record<HypothesisState, string> = {
  unverified: 'text-amber-300',
  verified: 'text-emerald-300',
  invalidated: 'text-red-300',
  archived: 'text-zinc-500',
};

type EvidenceKind = 'supporting' | 'counter';

/**
 * Hypothesis Profile — answers "why this hypothesis?". Layered
 * sections: Hero → Overview → Origin → Evidence → Linked observations
 * → System.
 *
 * Origin / Evidence / Observations come from
 * `/api/admin/learning/hypotheses/:id/lineage`. That endpoint degrades
 * gracefully: on 404/405/501 the Hero + Overview stay live so the
 * admin action bar still works, with a 'Lineage pending' card in
 * place of the missing sections.
 */
@Component({
  selector: 'app-hypothesis-profile-page',
  standalone: true,
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

  protected readonly hypothesis = computed(() =>
    this.hypothesisResource.value(),
  );
  protected readonly lineage = computed(() => this.lineageResource.value());

  protected readonly isLoading = computed(
    () => this.hypothesisResource.status() === 'loading' && !this.hypothesis(),
  );
  protected readonly hasError = computed(
    () => this.hypothesisResource.status() === 'error',
  );
  /**
   * "Pending" only when the backend returns 404/405/501 — the endpoint
   * isn't live yet. Transient 5xx / network errors fall through to the
   * regular error path so they don't masquerade as missing API.
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

  // Add-evidence form (inline within the profile).
  protected readonly evidenceKind = signal<EvidenceKind>('supporting');
  protected readonly evidenceBody = signal('');
  protected readonly isEvidenceFormOpen = signal(false);

  // Lifecycle: hypothesis transitions from
  // unverified → {verified | invalidated | archived}. Verify and
  // Invalidate share the same gate intentionally.
  protected readonly canVerify = computed(() => {
    const h = this.hypothesis();
    return !!h && h.state === 'unverified';
  });
  protected readonly canInvalidate = this.canVerify;
  // Any non-archived state can archive.
  protected readonly canArchive = computed(() => {
    const h = this.hypothesis();
    return !!h && h.state !== 'archived';
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
