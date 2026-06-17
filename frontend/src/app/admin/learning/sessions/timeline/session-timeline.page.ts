import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  SessionAttempt,
  SessionDetail,
} from '../../../../core/models/learning.model';

/**
 * Session Timeline Hero with domain /
 * mode / duration, main timeline of attempts (target + outcome +
 * observations), side rail with summary metrics and linked reflection
 * note if present. .
 */
@Component({
  selector: 'app-session-timeline-page',
  imports: [DatePipe, RouterLink],
  templateUrl: './session-timeline.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class SessionTimelinePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<SessionDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.learningService.session(params),
  });

  /**
   * View-model over the {session, attempts} wire: flattens the session row,
   * normalizes each attempt's observations to an array, and derives the
   * completion summary client-side (the endpoint ships no summary block).
   */
  protected readonly session = computed(() => {
    const detail = this.resource.value();
    if (!detail) return undefined;
    const attempts = detail.attempts.map((a) => ({
      ...a,
      observations: a.observations ?? [],
    }));
    return {
      ...detail.session,
      attempts,
      summary: {
        attempts: attempts.length,
        solved_independent: attempts.filter((a) =>
          a.outcome.startsWith('solved_independent'),
        ).length,
        solved_with_hint: attempts.filter((a) =>
          a.outcome.startsWith('solved_with_hint'),
        ).length,
        observations: attempts.reduce((n, a) => n + a.observations.length, 0),
      },
    };
  });
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.session(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly endpointsUnavailable = computed(() => {
    if (this.resource.status() !== 'error') return false;
    const err = this.resource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  protected readonly durationLabel = computed(() => {
    const s = this.session();
    if (!s) return '';
    const start = new Date(s.started_at).getTime();
    const end = s.ended_at ? new Date(s.ended_at).getTime() : Date.now();
    const minutes = Math.max(0, Math.round((end - start) / 60000));
    const hours = Math.floor(minutes / 60);
    const m = minutes % 60;
    return hours > 0 ? `${hours}h ${m}m` : `${m}m`;
  });

  protected readonly solvedPercent = computed(() => {
    const s = this.session();
    if (!s || s.summary.attempts === 0) return 0;
    return Math.round(
      (s.summary.solved_independent / s.summary.attempts) * 100,
    );
  });

  constructor() {
    this.topbar.set({
      title: 'Learning session',
      crumbs: ['Learning', 'Sessions'],
    });

    effect(() => {
      const s = this.session();
      if (!s) return;
      this.topbar.set({
        title: `Session · ${s.domain} · ${s.mode}`,
        crumbs: ['Learning', 'Sessions', s.id.slice(0, 8)],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected back(): void {
    this.router.navigate(['/admin/learning']);
  }

  protected outcomeClass(outcome: string): string {
    if (outcome.startsWith('solved_independent')) return 'text-emerald-300';
    if (outcome.startsWith('solved_with_hint')) return 'text-brand';
    if (outcome.startsWith('failed')) return 'text-red-300';
    return 'text-fg-muted';
  }

  protected attemptObsCount(a: SessionAttempt): number {
    return a.observations?.length ?? 0;
  }
}
