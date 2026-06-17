import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { GtdRowComponent } from './gtd-row.component';
import type { TodoRow } from '../../../core/services/todo.service';
import type { GtdView } from './gtd-view';

function makeRow(partial: Partial<TodoRow> = {}): TodoRow {
  return {
    id: 'todo-1',
    title: 'Sharpen the saw',
    state: 'todo',
    created_at: '2026-06-09T00:00:00Z',
    updated_at: '2026-06-09T00:00:00Z',
    ...partial,
  };
}

describe('GtdRowComponent', () => {
  let fixture: ComponentFixture<GtdRowComponent>;

  function render(item: TodoRow, view: GtdView, selected = false): void {
    fixture = TestBed.createComponent(GtdRowComponent);
    fixture.componentRef.setInput('item', item);
    fixture.componentRef.setInput('view', view);
    fixture.componentRef.setInput('selected', selected);
    fixture.detectChanges();
  }

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  it('should render the inbox variant with Clarify, defer, and drop actions', () => {
    render(makeRow({ state: 'inbox', created_by: 'system' }), 'inbox');

    expect(testid('gtd-row-clarify')).toBeTruthy();
    expect(testid('gtd-row-defer')).toBeTruthy();
    expect(testid('gtd-row-drop')).toBeTruthy();
    expect(testid('gtd-row-check')).toBeNull();
    expect(el().textContent).toContain('system');
  });

  it('should emit clarify / deferRow / dropRow from the inbox actions', () => {
    render(makeRow({ state: 'inbox' }), 'inbox');
    const clarified: unknown[] = [];
    const deferred: unknown[] = [];
    const dropped: unknown[] = [];
    fixture.componentInstance.clarify.subscribe(() => clarified.push(true));
    fixture.componentInstance.deferRow.subscribe(() => deferred.push(true));
    fixture.componentInstance.dropRow.subscribe(() => dropped.push(true));

    testid('gtd-row-clarify')?.click();
    testid('gtd-row-defer')?.click();
    testid('gtd-row-drop')?.click();

    expect(clarified).toHaveLength(1);
    expect(deferred).toHaveLength(1);
    expect(dropped).toHaveLength(1);
  });

  it('should show Start with project, energy, due, and pull on a pending row', () => {
    render(
      makeRow({
        project_title: 'koopa-core',
        energy: 'high',
        due: '2099-01-05T00:00:00Z',
      }),
      'pending',
    );

    expect(testid('gtd-row-advance')?.textContent).toContain('Start');
    expect(testid('gtd-row-pull')).toBeTruthy();
    expect(testid('gtd-row-defer')).toBeTruthy();
    expect(testid('gtd-row-due')?.textContent).toContain('Jan 5');
    expect(el().querySelector('app-energy-meter')).toBeTruthy();
    expect(el().textContent).toContain('koopa-core');
  });

  it('should show Complete and the in-progress pill when the todo is started', () => {
    render(makeRow({ state: 'in_progress' }), 'today');

    expect(testid('gtd-row-advance')?.textContent).toContain('Complete');
    expect(testid('gtd-row-ip-dot')).toBeTruthy();
    expect(el().textContent).toContain('in progress');
  });

  it('should hide defer, offer pull, and label the verb Activate on someday rows', () => {
    render(makeRow({ state: 'someday' }), 'someday');

    expect(testid('gtd-row-defer')).toBeNull();
    expect(testid('gtd-row-pull')).toBeTruthy();
    expect(testid('gtd-row-advance')?.textContent).toContain('Activate');
  });

  it('should mark the host when selected', () => {
    render(makeRow(), 'pending', true);
    expect(el().getAttribute('data-selected')).toBe('true');
  });
});
