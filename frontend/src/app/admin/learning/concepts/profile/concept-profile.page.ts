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
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { map } from 'rxjs';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  ConceptProfile,
  MasteryStage,
  ObservationConfidence,
} from '../../../../core/models/learning.model';

const STAGE_TEXT: Record<MasteryStage, string> = {
  struggling: 'text-red-300',
  developing: 'text-sky-300',
  solid: 'text-emerald-300',
};

const STAGE_DOT: Record<MasteryStage, string> = {
  struggling: 'bg-red-500',
  developing: 'bg-sky-400',
  solid: 'bg-emerald-500',
};

/**
 * Concept Profile Hero / Mastery
 * evidence / Hierarchy / Linked notes / Linked contents / Recent
 * attempts / Observations.  — gracefully degrades on 404/405/501.
 */
@Component({
  selector: 'app-concept-profile-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
  templateUrl: './concept-profile.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ConceptProfilePageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly slugFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('slug') ?? '')),
    { initialValue: '' },
  );

  protected readonly confidenceFilterOptions: readonly (
    | ObservationConfidence
    | 'all'
  )[] = ['high', 'all'];

  protected readonly confidenceFilter = signal<ObservationConfidence | 'all'>(
    'high',
  );

  protected readonly resource = rxResource<
    ConceptProfile,
    { slug: string; filter: ObservationConfidence | 'all' }
  >({
    params: () => ({
      slug: this.slugFromRoute(),
      filter: this.confidenceFilter(),
    }),
    stream: ({ params }) =>
      this.learningService.concept(params.slug, params.filter),
  });

  protected readonly concept = computed(() => this.resource.value());
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.concept(),
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

  constructor() {
    this.topbar.set({
      title: 'Concept',
      crumbs: ['Learning', 'Concepts'],
    });

    effect(() => {
      const c = this.concept();
      if (!c) return;
      this.topbar.set({
        title: `Concept · ${c.slug}`,
        crumbs: ['Learning', 'Concepts', c.slug],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setConfidenceFilter(value: ObservationConfidence | 'all'): void {
    this.confidenceFilter.set(value);
  }

  protected back(): void {
    this.router.navigate(['/admin/learning/concepts']);
  }

  protected stageText(s: MasteryStage): string {
    return STAGE_TEXT[s];
  }

  protected stageDot(s: MasteryStage): string {
    return STAGE_DOT[s];
  }
}
