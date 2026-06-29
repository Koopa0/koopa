import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { RecurrenceModalComponent } from './recurrence-modal.component';
import type {
  RecurrenceRequest,
  TodoRow,
} from '../../../core/services/todo.service';

const oneOff: TodoRow = {
  id: 'todo-1',
  title: 'Memorize Japanese vocab',
  state: 'in_progress',
  created_at: '2026-06-10T08:00:00Z',
  updated_at: '2026-06-10T08:00:00Z',
};

const intervalRow: TodoRow = {
  ...oneOff,
  recur_interval: 3,
  recur_unit: 'weeks',
};

describe('RecurrenceModalComponent', () => {
  let fixture: ComponentFixture<RecurrenceModalComponent>;

  function render(item: TodoRow = oneOff): RecurrenceRequest[] {
    fixture = TestBed.createComponent(RecurrenceModalComponent);
    fixture.componentRef.setInput('item', item);
    fixture.detectChanges();
    const emitted: RecurrenceRequest[] = [];
    fixture.componentInstance.saved.subscribe((r) => emitted.push(r));
    return emitted;
  }

  function testid(id: string): HTMLElement | null {
    return (fixture.nativeElement as HTMLElement).querySelector(
      `[data-testid="${id}"]`,
    );
  }

  it('should emit selected weekdays in week order regardless of click order', () => {
    const emitted = render();
    // Click Wed before Mon — the request must still list them mon,wed.
    testid('recurrence-day-wed')?.click();
    testid('recurrence-day-mon')?.click();
    fixture.detectChanges();
    testid('recurrence-save')?.click();
    expect(emitted).toEqual([{ weekdays: ['mon', 'wed'] }]);
  });

  it('should emit all seven weekdays when "Every day" is chosen', () => {
    const emitted = render();
    testid('recurrence-daily')?.click();
    fixture.detectChanges();
    testid('recurrence-save')?.click();
    expect(emitted).toEqual([
      { weekdays: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] },
    ]);
  });

  it('should not emit a weekday request when no day is selected', () => {
    const emitted = render();
    // Save is disabled with zero days — clicking it must emit nothing.
    testid('recurrence-save')?.click();
    expect(emitted).toEqual([]);
  });

  it('should prefill interval mode from an interval-mode row and emit interval+unit', () => {
    const emitted = render(intervalRow);
    const intervalInput = testid('recurrence-interval') as HTMLInputElement;
    expect(intervalInput.value).toBe('3');
    const unitSelect = testid('recurrence-unit') as HTMLSelectElement;
    expect(unitSelect.value).toBe('weeks');

    testid('recurrence-save')?.click();
    expect(emitted).toEqual([{ interval: 3, unit: 'weeks' }]);
  });

  it('should emit an interval request after switching to Every N and editing it', () => {
    const emitted = render();
    testid('recurrence-mode-interval')?.click();
    fixture.detectChanges();
    const intervalInput = testid('recurrence-interval') as HTMLInputElement;
    intervalInput.value = '2';
    intervalInput.dispatchEvent(new Event('input'));
    const unitSelect = testid('recurrence-unit') as HTMLSelectElement;
    unitSelect.value = 'days';
    unitSelect.dispatchEvent(new Event('change'));
    fixture.detectChanges();

    testid('recurrence-save')?.click();
    expect(emitted).toEqual([{ interval: 2, unit: 'days' }]);
  });

  it('should emit a clear request from the Clear recurrence action', () => {
    const emitted = render(intervalRow);
    testid('recurrence-clear')?.click();
    expect(emitted).toEqual([{ clear: true }]);
  });

  it('should emit closed from Cancel', () => {
    render();
    let closed = 0;
    fixture.componentInstance.closed.subscribe(() => closed++);
    testid('recurrence-cancel')?.click();
    expect(closed).toBe(1);
  });
});
