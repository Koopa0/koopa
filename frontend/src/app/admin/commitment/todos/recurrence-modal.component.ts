import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  linkedSignal,
  output,
  signal,
} from '@angular/core';
import type {
  RecurrenceRequest,
  RecurUnit,
  TodoRow,
  TodoWeekday,
} from '../../../core/services/todo.service';
import { ModalComponent } from '../../../shared/components/modal/modal.component';
import { FormFieldComponent } from '../../../shared/components/form-field/form-field.component';

/** Weekday toggle, in week order. value matches the backend abbreviation. */
interface WeekdayToggle {
  value: TodoWeekday;
  label: string;
}

const WEEKDAYS: readonly WeekdayToggle[] = [
  { value: 'mon', label: 'Mon' },
  { value: 'tue', label: 'Tue' },
  { value: 'wed', label: 'Wed' },
  { value: 'thu', label: 'Thu' },
  { value: 'fri', label: 'Fri' },
  { value: 'sat', label: 'Sat' },
  { value: 'sun', label: 'Sun' },
];

const UNITS: readonly RecurUnit[] = ['days', 'weeks', 'months', 'years'];

type RecurMode = 'weekly' | 'interval';

/**
 * Recurrence editor — turns a todo into a routine (weekday-mode or
 * interval-mode) or clears its schedule. Owns the form state and emits the
 * RecurrenceRequest; the GTD store owns the round-trip (PUT .../recurrence).
 * Pure picker — does not know which todo it edits beyond the title shown.
 */
@Component({
  selector: 'app-recurrence-modal',
  imports: [ModalComponent, FormFieldComponent],
  templateUrl: './recurrence-modal.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RecurrenceModalComponent {
  readonly item = input.required<TodoRow>();
  readonly busy = input(false);

  readonly saved = output<RecurrenceRequest>();
  readonly closed = output<void>();

  protected readonly weekdays = WEEKDAYS;
  protected readonly units = UNITS;

  // linkedSignal defers reading the required input until after it is set
  // (a field initializer reading item() would throw). Interval-mode rows
  // prefill from the row's existing schedule; weekday-mode state is not on the
  // list wire, so the picker starts empty and the save overwrites. Default to
  // weekly, the common "daily routine" shape.
  protected readonly mode = linkedSignal<RecurMode>(() =>
    (this.item().recur_interval ?? 0) > 0 ? 'interval' : 'weekly',
  );
  protected readonly selected = signal<ReadonlySet<TodoWeekday>>(new Set());
  protected readonly interval = linkedSignal(() => this.item().recur_interval ?? 1);
  protected readonly unit = linkedSignal<RecurUnit>(
    () => (this.item().recur_unit as RecurUnit) ?? 'days',
  );

  /** Weekday mode needs at least one day; interval needs a positive count. */
  protected readonly canSave = computed(() =>
    this.mode() === 'weekly' ? this.selected().size > 0 : this.interval() > 0,
  );

  protected isSelected(day: TodoWeekday): boolean {
    return this.selected().has(day);
  }

  protected toggleDay(day: TodoWeekday): void {
    this.selected.update((current) => {
      const next = new Set(current);
      if (next.has(day)) {
        next.delete(day);
      } else {
        next.add(day);
      }
      return next;
    });
  }

  protected selectAllDays(): void {
    this.selected.set(new Set(WEEKDAYS.map((w) => w.value)));
  }

  protected readInterval(event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    this.interval.set(Number.isFinite(value) && value > 0 ? value : 1);
  }

  protected readUnit(event: Event): void {
    this.unit.set((event.target as HTMLSelectElement).value as RecurUnit);
  }

  protected save(): void {
    if (!this.canSave()) return;
    if (this.mode() === 'weekly') {
      this.saved.emit({
        weekdays: WEEKDAYS.map((w) => w.value).filter((d) =>
          this.selected().has(d),
        ),
      });
      return;
    }
    this.saved.emit({ interval: this.interval(), unit: this.unit() });
  }

  protected clear(): void {
    this.saved.emit({ clear: true });
  }
}
