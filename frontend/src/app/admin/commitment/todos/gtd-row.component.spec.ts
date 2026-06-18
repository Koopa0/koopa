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

  it('should render the capture description under the title on an inbox row', () => {
    render(
      makeRow({ state: 'inbox', description: 'check HNSW vs IVFFlat tradeoffs' }),
      'inbox',
    );

    expect(testid('gtd-row-description')?.textContent).toContain(
      'check HNSW vs IVFFlat tradeoffs',
    );
  });

  it('should omit the description line on an inbox row with no detail', () => {
    render(makeRow({ state: 'inbox' }), 'inbox');

    expect(testid('gtd-row-description')).toBeNull();
  });

  it('should strip markdown from the description preview on an inbox row', () => {
    render(
      makeRow({
        state: 'inbox',
        description:
          '**Move** the JWT parsing into a `dedicated` [middleware](https://x)',
      }),
      'inbox',
    );

    const preview = testid('gtd-row-description')?.textContent ?? '';
    expect(preview).not.toContain('**');
    expect(preview).not.toContain('`');
    expect(preview).not.toContain('](');
    expect(preview).toContain('Move');
    expect(preview).toContain('dedicated');
    expect(preview).toContain('middleware');
  });

  it('should emit openDetail from the row body without firing it from Clarify', () => {
    render(makeRow({ state: 'inbox' }), 'inbox');
    const opened: unknown[] = [];
    const clarified: unknown[] = [];
    fixture.componentInstance.openDetail.subscribe(() => opened.push(true));
    fixture.componentInstance.clarify.subscribe(() => clarified.push(true));

    testid('gtd-row-open')?.click();
    expect(opened).toHaveLength(1);

    // The Clarify action is a sibling of the open-detail button, not nested
    // inside it — clicking it must not also bubble an openDetail emission.
    testid('gtd-row-clarify')?.click();
    expect(opened).toHaveLength(1);
    expect(clarified).toHaveLength(1);
  });

  it('should mark a human inbox capture as a manual source', () => {
    render(makeRow({ state: 'inbox', created_by: 'human' }), 'inbox');

    expect(testid('gtd-row-source')?.getAttribute('data-source')).toBe(
      'manual',
    );
  });

  it('should mark an agent inbox capture (hermes) as an agent source', () => {
    render(makeRow({ state: 'inbox', created_by: 'hermes' }), 'inbox');

    expect(testid('gtd-row-source')?.getAttribute('data-source')).toBe('agent');
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
