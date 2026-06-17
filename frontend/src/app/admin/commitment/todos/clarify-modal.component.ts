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
import { ModalComponent } from '../../../shared/components/modal/modal.component';
import { FormFieldComponent } from '../../../shared/components/form-field/form-field.component';
import { energyOf, type ClarifyResult } from './gtd-view';

const ENERGY_OPTIONS: readonly EnergyLevel[] = ['low', 'medium', 'high'];

/**
 * Clarify dialog for an inbox capture: give it just enough shape to
 * act on — project, energy, due date. No field is required. This
 * dialog only collects form state; the page-level store owns the
 * PUT + advance(clarify) round-trip.
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
  readonly closed = output<void>();

  private readonly planService = inject(PlanService);

  protected readonly energyOptions = ENERGY_OPTIONS;

  private readonly projectsResource = rxResource({
    stream: () => this.planService.getProjectsOverview(),
  });
  protected readonly projects = computed(
    () => this.projectsResource.value()?.projects ?? [],
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
}
