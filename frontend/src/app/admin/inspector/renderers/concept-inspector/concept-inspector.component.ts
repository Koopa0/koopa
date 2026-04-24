import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { LucideAngularModule, Copy as CopyIcon } from 'lucide-angular';
import { ConceptService } from '../../../../core/services/concept.service';
import { InspectorService } from '../../inspector.service';
import type {
  ConceptDetail,
  ConceptObservation,
  MasteryStage,
  ObservationSignal,
  ObservationSeverity,
} from '../../../../core/models/workbench.model';

const STAGE_TEXT_CLASS: Record<MasteryStage, string> = {
  developing: 'text-zinc-400',
  struggling: 'text-amber-400',
  solid: 'text-emerald-400',
};

const SIGNAL_LABEL_CLASS: Record<ObservationSignal, string> = {
  weakness: 'text-red-400',
  improvement: 'text-sky-400',
  mastery: 'text-emerald-400',
};

const SEVERITY_CLASS: Record<ObservationSeverity, string> = {
  critical: 'text-red-300',
  moderate: 'text-amber-300',
  minor: 'text-zinc-400',
};

const OUTCOME_ICON: Record<string, { icon: string; label: string }> = {
  solved_independent: { icon: '✓', label: 'solved independently' },
  solved_with_hint: { icon: '△', label: 'solved with hint' },
  stuck: { icon: '✗', label: 'stuck' },
  skipped: { icon: '○', label: 'skipped' },
};

interface ObservationGroup {
  signal_type: ObservationSignal;
  label: string;
  high: ConceptObservation[];
}

/**
 * Concept Inspector — single-tab layout with three sections:
 *   Mastery  — inline counts of weakness / improvement / mastery obs.
 *   Recent attempts — top-5 mini list.
 *   Observations — grouped by signal_type. Low-confidence rows live in
 *     a `<details>` disclosure; use the slug (not UUID) as the copy
 *     handle for Cowork prompts.
 *
 * Data source: `GET /api/admin/learning/concepts/{id}`.
 */
@Component({
  selector: 'app-concept-inspector',
  standalone: true,
  imports: [DatePipe, ClipboardModule, RouterLink, LucideAngularModule],
  templateUrl: './concept-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ConceptInspectorComponent {
  readonly id = input.required<string>();

  private readonly conceptService = inject(ConceptService);
  protected readonly inspector = inject(InspectorService);

  protected readonly justCopied = signal(false);
  protected readonly CopyIcon = CopyIcon;

  protected readonly resource = rxResource<ConceptDetail, string>({
    params: () => this.id(),
    stream: ({ params }) => this.conceptService.get(params),
  });

  protected readonly concept = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /** Stage colored text class (subtitle inline, not banner). */
  protected readonly stageClass = computed(() => {
    const c = this.concept();
    return c ? STAGE_TEXT_CLASS[c.mastery_stage] : 'text-zinc-400';
  });

  /** Group high-confidence observations by signal_type for OBSERVATIONS section. */
  protected readonly observationGroups = computed<ObservationGroup[]>(() => {
    const c = this.concept();
    if (!c) return [];
    const groups: ObservationGroup[] = [
      { signal_type: 'weakness', label: 'Weaknesses', high: [] },
      { signal_type: 'improvement', label: 'Improvements', high: [] },
      { signal_type: 'mastery', label: 'Mastery', high: [] },
    ];
    for (const obs of c.recent_observations) {
      const grp = groups.find((g) => g.signal_type === obs.signal_type);
      if (grp) grp.high.push(obs);
    }
    return groups.filter((g) => g.high.length > 0);
  });

  /** Outcome icon + label for SR-friendly attempt rows. */
  protected outcome(value: string): { icon: string; label: string } {
    return OUTCOME_ICON[value] ?? { icon: '·', label: value };
  }

  protected signalLabelClass(signal: ObservationSignal): string {
    return SIGNAL_LABEL_CLASS[signal] + ' text-xs uppercase tracking-wider';
  }

  protected severityClass(severity: ObservationSeverity): string {
    return SEVERITY_CLASS[severity];
  }

  protected onCopyConceptSlug(): void {
    this.justCopied.set(true);
    setTimeout(() => this.justCopied.set(false), 1500);
  }
}
