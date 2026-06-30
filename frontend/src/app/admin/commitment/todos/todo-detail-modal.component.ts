import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
} from '@angular/core';
import type { TodoRow } from '../../../core/services/todo.service';
import { ModalComponent } from '../../../shared/components/modal/modal.component';
import { EnergyMeterComponent } from '../../../shared/components/energy-meter/energy-meter.component';
import { advanceActionFor, energyOf, recurLabel } from './gtd-view';
import type { EnergyLevel } from '../../../core/models/workbench.model';

/** The next advance verb's button label, by state; null when there is none. */
const ADVANCE_LABEL: Record<'start' | 'activate' | 'complete', string> = {
  start: 'Start',
  activate: 'Activate',
  complete: 'Complete',
};

/**
 * Todo detail panel — opens on a row click to surface, in one discoverable
 * place, what the row is (state, project, due, energy, whether it is a recurring
 * routine) and the actions previously hidden behind hover/keyboard: advance its
 * state, defer it, edit its recurrence, or drop it. A pure view — the GTD store
 * owns every round-trip; this emits intent against the open detail target.
 */
@Component({
  selector: 'app-todo-detail-modal',
  imports: [ModalComponent, EnergyMeterComponent],
  templateUrl: './todo-detail-modal.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodoDetailModalComponent {
  readonly item = input.required<TodoRow>();
  readonly busy = input(false);

  readonly advance = output<void>();
  readonly deferRow = output<void>();
  readonly dropRow = output<void>();
  readonly editRecurrence = output<void>();
  readonly closed = output<void>();

  /** Human label for the state pill (in_progress → "in progress"). */
  protected readonly stateLabel = computed(() =>
    this.item().state.replaceAll('_', ' '),
  );

  /** The next advance verb's label, or null at a terminal state. */
  protected readonly advanceLabel = computed(() => {
    const action = advanceActionFor(this.item().state);
    return action ? ADVANCE_LABEL[action] : null;
  });

  /** Someday rows re-enter the backlog via Activate; they cannot be deferred. */
  protected readonly showDefer = computed(() => this.item().state !== 'someday');

  /** Recurrence summary ("every 2w" / "Mon Thu" / "daily"), null if one-time. */
  protected readonly recurrence = computed(() =>
    recurLabel(
      this.item().recur_interval,
      this.item().recur_unit,
      this.item().recur_weekdays,
    ),
  );

  protected readonly energy = computed((): EnergyLevel | null =>
    energyOf(this.item().energy),
  );

  protected readonly due = computed(() => this.item().due?.slice(0, 10) ?? null);
}
