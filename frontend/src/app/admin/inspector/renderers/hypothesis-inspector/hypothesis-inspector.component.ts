import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe, JsonPipe } from '@angular/common';
import { HypothesisService } from '../../../../core/services/hypothesis.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { InspectorService } from '../../inspector.service';
import type { Hypothesis } from '../../../../core/models/workbench.model';

type HypothesisTab = 'claim' | 'evidence';

/**
 * Hypothesis Inspector renderer — Claim tab + Evidence tab.
 * Action bar: Verify / Invalidate / Add Evidence / Archive.
 */
@Component({
  selector: 'app-hypothesis-inspector',
  standalone: true,
  imports: [DatePipe, JsonPipe],
  templateUrl: './hypothesis-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HypothesisInspectorComponent {
  readonly id = input.required<string>();

  private readonly hypothesisService = inject(HypothesisService);
  private readonly inspector = inject(InspectorService);
  private readonly notifications = inject(NotificationService);

  protected readonly activeTab = signal<HypothesisTab>('claim');
  protected readonly isActioning = signal(false);

  protected readonly resource = rxResource<Hypothesis, string>({
    params: () => this.id(),
    stream: ({ params }) => this.hypothesisService.get(params),
  });

  protected readonly hypothesis = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly evidence = computed(() => {
    const meta = this.hypothesis()?.metadata;
    if (!meta?.supporting_evidence) return [];
    return meta.supporting_evidence as unknown[];
  });

  protected readonly isActionable = computed(() => {
    return this.hypothesis()?.state === 'unverified';
  });

  protected setTab(tab: HypothesisTab): void {
    this.activeTab.set(tab);
  }

  protected verify(): void {
    const h = this.hypothesis();
    if (!h || this.isActioning()) return;

    this.isActioning.set(true);
    this.hypothesisService.verify(h.id).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.inspector.recordAction('hypothesis', h.id, 'verify');
        this.notifications.undo(`Verified "${h.claim}"`, () => {
          // Undo not feasible for state transitions — just reload
          this.resource.reload();
        });
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to verify hypothesis.');
      },
    });
  }

  protected invalidate(): void {
    const h = this.hypothesis();
    if (!h || this.isActioning()) return;

    this.isActioning.set(true);
    this.hypothesisService.invalidate(h.id).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.inspector.recordAction('hypothesis', h.id, 'invalidate');
        this.notifications.success(`Invalidated "${h.claim}"`);
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to invalidate hypothesis.');
      },
    });
  }

  protected archive(): void {
    const h = this.hypothesis();
    if (!h || this.isActioning()) return;

    this.isActioning.set(true);
    this.hypothesisService.archive(h.id).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.resource.reload();
        this.notifications.success('Hypothesis archived.');
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to archive hypothesis.');
      },
    });
  }
}
