import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  output,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { PlanService } from '../../../core/services/plan.service';
import type { TodoRow } from '../../../core/services/todo.service';
import type { EnergyLevel } from '../../../core/models/workbench.model';
import { MarkdownService } from '../../../core/services/markdown.service';
import { ModalComponent } from '../../../shared/components/modal/modal.component';
import { FormFieldComponent } from '../../../shared/components/form-field/form-field.component';
import { energyOf, type ClarifyResult } from './gtd-view';

const ENERGY_OPTIONS: readonly EnergyLevel[] = ['low', 'medium', 'high'];

/**
 * Inbox capture detail + triage dialog. Renders the capture's full markdown
 * body (read-first) above the clarify form — project, energy, due date, none
 * required — and hosts the full triage decision set in its footer: clarify
 * (the primary "shape it into a todo"), defer, and drop. This dialog collects
 * form state and emits intent; the page-level store owns every round-trip
 * (PUT + advance(clarify), defer, drop).
 */
@Component({
  selector: 'app-clarify-modal',
  imports: [ModalComponent, FormFieldComponent],
  templateUrl: './clarify-modal.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ClarifyModalComponent {
  readonly item = input.required<TodoRow>();
  readonly busy = input(false);

  readonly clarified = output<ClarifyResult>();
  readonly deferInstead = output<void>();
  readonly dropInstead = output<void>();
  readonly closed = output<void>();

  private readonly planService = inject(PlanService);
  private readonly markdownService = inject(MarkdownService);

  protected readonly energyOptions = ENERGY_OPTIONS;

  // Rendered capture body. MarkdownService sanitizes via DOMPurify, so the
  // result is safe for [innerHTML]; decorateCaptureHtml then adapts it for the
  // dialog (new-tab links, headings demoted under the dialog's own h3 title).
  protected readonly renderedDescription = computed(() => {
    const body = this.item().description;
    return body ? this.decorateCaptureHtml(this.markdownService.parse(body)) : '';
  });

  private readonly projectsResource = rxResource({
    stream: () => this.planService.getProjectsOverview(),
  });
  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). The value is the
  // project array directly (getProjectsOverview unwraps {data:[...]}).
  protected readonly projects = computed(() =>
    this.projectsResource.hasValue() ? this.projectsResource.value() : [],
  );

  protected readonly project = signal('');
  protected readonly energy = linkedSignal<EnergyLevel>(
    () => energyOf(this.item().energy) ?? 'medium',
  );
  protected readonly due = signal('');

  protected readValue(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  protected submit(): void {
    this.clarified.emit({
      project_id: this.project() || null,
      energy: this.energy(),
      due: this.due() || null,
    });
  }

  // Adapt the already-sanitized capture HTML for the dialog. Runs after
  // MarkdownService's DOMPurify pass; Angular re-sanitizes on [innerHTML] bind.
  private decorateCaptureHtml(html: string): string {
    return (
      html
        // Demote body headings to h4 so a capture's `# Title` doesn't emit an
        // <h1> under the dialog's own <h3> title (WCAG 1.3.1 / 2.4.6).
        .replace(/<(\/?)h[1-6]\b/gi, '<$1h4')
        // Links open in a new tab; overwrite any source-set target/rel so the
        // noopener guard always wins (no duplicate attributes).
        .replace(/<a\b([^>]*)>/gi, (_match, attrs: string) => {
          const cleaned = attrs.replace(/\s+(?:target|rel)="[^"]*"/gi, '');
          return `<a${cleaned} target="_blank" rel="noopener noreferrer">`;
        })
    );
  }
}
