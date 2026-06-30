import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { TodoDetailModalComponent } from './todo-detail-modal.component';
import type { TodoRow } from '../../../core/services/todo.service';

function makeRow(partial: Partial<TodoRow> = {}): TodoRow {
  return {
    id: 't1',
    title: 'Rewrite the auth handler',
    state: 'todo',
    created_at: '2026-06-10T00:00:00Z',
    updated_at: '2026-06-10T00:00:00Z',
    ...partial,
  };
}

describe('TodoDetailModalComponent', () => {
  let fixture: ComponentFixture<TodoDetailModalComponent>;

  function render(row: TodoRow): void {
    TestBed.configureTestingModule({ imports: [TodoDetailModalComponent] });
    fixture = TestBed.createComponent(TodoDetailModalComponent);
    fixture.componentRef.setInput('item', row);
    fixture.detectChanges();
  }

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  afterEach(() => TestBed.resetTestingModule());

  it('should label the advance verb Start for a todo and show one-time recurrence', () => {
    render(makeRow({ state: 'todo' }));
    expect(testid('todo-detail-advance')?.textContent).toContain('Start');
    expect(testid('todo-detail-recurrence')?.textContent).toContain('One-time');
    expect(testid('todo-detail-defer')).toBeTruthy();
  });

  it('should label the advance verb Complete for an in-progress todo', () => {
    render(makeRow({ state: 'in_progress' }));
    expect(testid('todo-detail-advance')?.textContent).toContain('Complete');
  });

  it('should show the recurrence badge and Edit-routine label for a routine', () => {
    render(makeRow({ recur_interval: 2, recur_unit: 'weeks' }));
    expect(testid('todo-detail-recurrence')?.textContent).toContain('every 2w');
    expect(testid('todo-detail-recurrence-edit')?.textContent).toContain(
      'Edit routine',
    );
  });

  it('should hide Defer and offer Activate on a someday row', () => {
    render(makeRow({ state: 'someday' }));
    expect(testid('todo-detail-defer')).toBeNull();
    expect(testid('todo-detail-advance')?.textContent).toContain('Activate');
  });

  it('should emit the action outputs when the footer buttons are clicked', () => {
    render(makeRow({ state: 'todo' }));
    let advanced = 0;
    let deferred = 0;
    let dropped = 0;
    let editedRecurrence = 0;
    fixture.componentInstance.advance.subscribe(() => advanced++);
    fixture.componentInstance.deferRow.subscribe(() => deferred++);
    fixture.componentInstance.dropRow.subscribe(() => dropped++);
    fixture.componentInstance.editRecurrence.subscribe(() => editedRecurrence++);

    (testid('todo-detail-advance') as HTMLButtonElement).click();
    (testid('todo-detail-defer') as HTMLButtonElement).click();
    (testid('todo-detail-drop') as HTMLButtonElement).click();
    (testid('todo-detail-recurrence-edit') as HTMLButtonElement).click();

    expect([advanced, deferred, dropped, editedRecurrence]).toEqual([1, 1, 1, 1]);
  });
});
